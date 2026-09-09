# SPDX-License-Identifier: Apache-2.0
"""peer_accountability_tab.py: Pane B "Peers" -- one row per node exchanged
with, every cell honestly labeled and never blank.

Focus of these tests: (1) peer grouping never fabricates one identified node
out of unattributed exchanges; (2) the Rung column never rounds a peer's row
up past its weakest exchange; (3) History/Continuity/Witnessed correctly
flip to a red/failed state -- with the two signed checkpoints attached --
when this node's own checkpoint chain forks, and never do assuming an
unbroken chain when the checkpoint lines say otherwise; (4) the
refusal/absence/pending cell states render their exact required text and
NEVER blank; (5) sorting is refused outright for any trust/score-shaped key
and works for every other property.
"""
from __future__ import annotations

import copy
import json

import pytest

import checkpointing
from capsule_emit.checkpoint import WitnessRecord, CheckpointConfig
from checkpointing import CheckpointState, Ed25519Signer, JsonlLogSource

from peer_accountability_tab import (
    ASKED_ABSENT_REASON,
    CELL_ABSENT,
    CELL_CONTRADICTED,
    CELL_FAILED,
    CELL_PENDING,
    CELL_PRESENT,
    CELL_REFUSED,
    CELL_UNILATERAL,
    CELL_VERIFIED,
    FORBIDDEN_RATING_KEYS,
    SERVED_PENDING_REASON,
    THEIRS_HISTORY_PENDING_REASON,
    VERDICTS_REFERENCES_PENDING_REASON,
    RatingFieldError,
    UNKNOWN_PEER,
    asked_cell,
    assert_no_rating_fields,
    build_peer_row,
    build_peers_payload,
    continuity_cell,
    group_by_peer,
    history_cell,
    node_cell,
    pair_cell,
    peer_history_cell,
    render_cell_text,
    render_peers_tab_html,
    role_and_count_cell,
    rung_cell,
    served_cell,
    sort_peer_rows,
    verdicts_cell,
    witnessed_cell,
)


# ---------------------------------------------------------------------------
# Fixtures: synthetic ledger records + a REAL checkpoint chain
# ---------------------------------------------------------------------------


def _capsule(*, capsule_id, timestamp, cross_party=None) -> dict:
    poc: dict = {"client_nonce_source": "client_supplied"}
    if cross_party is not None:
        poc["cross_party"] = cross_party
    return {
        "capsule_id": capsule_id,
        "operator": "op",
        "timestamp": timestamp,
        "model_attestation": {"model_id": "m", "compute_attestation": {"x-mesh-poc-v1": poc}},
        "effect": {"request_digest": "1" * 64, "response_digest": "2" * 64, "effect_attestation": "gate_executed"},
        "disposition": {"decision": "accept", "verdict_class": "executed"},
    }


def _exchange_capsule(
    *,
    capsule_id,
    role,
    exchange_id="ex-1",
    timestamp="2026-09-03T00:00:00Z",
    request_digest="a" * 64,
    response_digest="b" * 64,
    cross_party=None,
) -> dict:
    """Same shape `test_capsule_exchange_tab.py::_capsule` uses -- role +
    exchange_id + effect digests -- for the cells that fold over
    `capsule_exchange_tab`'s pairing machinery (pair_cell, verdicts_cell,
    role_and_count_cell)."""
    poc: dict = {
        "role": role,
        "serving_provenance": {
            "model": {"canonical_ref": "meta-llama/Llama-3.2-3B-Instruct"},
            "exchange_id": exchange_id,
        },
        "evidence_refs": {"binary_attestation": None, "tee_attestation": None},
    }
    if cross_party is not None:
        poc["cross_party"] = cross_party
    return {
        "capsule_id": capsule_id,
        "operator": "op",
        "timestamp": timestamp,
        "model_attestation": {"model_id": "m", "compute_attestation": {"x-mesh-poc-v1": poc}},
        "effect": {"request_digest": request_digest, "response_digest": response_digest, "effect_attestation": "gate_executed"},
        "disposition": {"decision": "accept", "verdict_class": "executed"},
    }


@pytest.fixture
def fake_witness(monkeypatch):
    calls = []

    def _fake_register_checkpoint(checkpoint_cose: bytes, ts_url, *, timeout=30.0):
        calls.append((checkpoint_cose, ts_url))
        return WitnessRecord(
            ts_url=ts_url,
            entry_hash=f"fake-entry-hash-{len(calls)}",
            receipt_b64="ZmFrZS1yZWNlaXB0",
            leaf_index=len(calls) - 1,
            tree_size=len(calls),
        )

    monkeypatch.setattr(checkpointing, "register_checkpoint", _fake_register_checkpoint)
    return calls


def _build_chain(tmp_path, n_checkpoints: int, *, log_id: str = "log-a", entries_per_checkpoint: int = 2):
    """A REAL chain of `n_checkpoints` COSE-wire-signed checkpoints, same
    helper shape as test_history_card.py's own -- never a hand-rolled
    fixture that would let the chain walk pass trivially."""
    log = JsonlLogSource(tmp_path / "capsules.jsonl")
    cfg = CheckpointConfig(cadence_entries=entries_per_checkpoint, max_lag_entries=10_000, ts_urls=["https://fake-ts.example"])
    signer = Ed25519Signer(tmp_path / "node-a.pem")
    state = CheckpointState.load(ledger_dir=tmp_path, log_source=log, cfg=cfg, signer=signer, log_id=log_id)

    n = 0
    made = 0
    while made < n_checkpoints:
        log.append({"capsule_id": f"{n:064x}", "n": n})
        n += 1
        if state.record_appended() is not None:
            made += 1

    lines = (tmp_path / "checkpoints.jsonl").read_text().splitlines()
    return [json.loads(line) for line in lines]


# ---------------------------------------------------------------------------
# group_by_peer / node_cell -- never fabricate one node out of "unknown"
# ---------------------------------------------------------------------------


def test_group_by_peer_groups_matching_initiator_ref_together():
    a1 = _capsule(capsule_id="a1", timestamp="2026-09-01T00:00:00Z", cross_party={"initiator_ref": "x" * 64})
    a2 = _capsule(capsule_id="a2", timestamp="2026-09-02T00:00:00Z", cross_party={"initiator_ref": "x" * 64})
    b1 = _capsule(capsule_id="b1", timestamp="2026-09-01T00:00:00Z", cross_party={"initiator_ref": "y" * 64})

    groups = group_by_peer([a1, a2, b1])

    assert set(groups.keys()) == {f"initiator:{'x'*12}", f"initiator:{'y'*12}"}
    assert len(groups[f"initiator:{'x'*12}"]) == 2


def test_group_by_peer_no_evidence_buckets_under_unknown():
    no_evidence = _capsule(capsule_id="c1", timestamp="2026-09-01T00:00:00Z", cross_party=None)

    groups = group_by_peer([no_evidence])

    assert list(groups.keys()) == [UNKNOWN_PEER]


def test_node_cell_unknown_peer_never_pretends_to_be_one_identified_node():
    records = [_capsule(capsule_id="c1", timestamp="t", cross_party=None), _capsule(capsule_id="c2", timestamp="t", cross_party=None)]

    cell = node_cell(UNKNOWN_PEER, records)

    assert cell["state"] == CELL_ABSENT
    assert cell["peer_id"] is None
    assert "not one identified peer" in cell["text"]
    assert render_cell_text(cell)  # never blank


def test_node_cell_identified_peer_renders_member_never_owner():
    records = [_capsule(capsule_id="c1", timestamp="t", cross_party={"initiator_ref": "x" * 64})]

    cell = node_cell("initiator:" + "x" * 12, records)

    assert cell["state"] == CELL_PRESENT
    assert cell["member_kind"] == "member"
    assert cell["text"] == "initiator:" + "x" * 12


# ---------------------------------------------------------------------------
# rung_cell -- worst-case, never rounds up
# ---------------------------------------------------------------------------


def test_rung_cell_worst_case_never_rounds_up_a_mixed_peer():
    unilateral = _capsule(capsule_id="c1", timestamp="t1", cross_party=None)
    acknowledged = _capsule(capsule_id="c2", timestamp="t2", cross_party={"initiator_ref": "x" * 64})

    cell = rung_cell([acknowledged, unilateral])

    assert cell["rung"] == "unilateral_fallback"
    assert cell["state"] == CELL_UNILATERAL
    assert set(cell["distinct_rungs"]) == {"unilateral_fallback", "acknowledged_receipt"}
    assert "worst of 2 distinct" in cell["text"]


def test_rung_cell_single_rung_no_distinct_note():
    same = [_capsule(capsule_id=f"c{i}", timestamp=f"t{i}", cross_party={"initiator_ref": "x" * 64}) for i in range(3)]

    cell = rung_cell(same)

    assert cell["rung"] == "acknowledged_receipt"
    assert cell["state"] == CELL_PRESENT
    assert cell["text"] == "acknowledged_receipt"


# ---------------------------------------------------------------------------
# history / continuity / witnessed -- shared per-log facts, honest on a fork
# ---------------------------------------------------------------------------


def test_history_cell_and_continuity_cell_are_green_on_an_unbroken_chain(tmp_path, fake_witness):
    lines = _build_chain(tmp_path, 4)
    from history_card import build_history_card

    card = build_history_card(node_id="node-a", log_id="log-a", checkpoint_lines=lines, since_size=0)

    hist = history_cell(card)
    cont = continuity_cell(card, lines)

    assert hist["state"] == CELL_VERIFIED
    assert cont["state"] == CELL_VERIFIED
    assert cont["text"] == "unbroken"
    assert "last_good_checkpoint" not in cont


def test_continuity_cell_is_absent_not_verified_when_there_are_no_checkpoints_at_all():
    from history_card import build_history_card

    card = build_history_card(node_id="node-a", log_id="log-a", checkpoint_lines=[], since_size=0)
    cell = continuity_cell(card, [])

    assert cell["state"] == CELL_ABSENT
    assert "last_good_checkpoint" not in cell


def test_continuity_cell_flips_red_on_a_fork_and_carries_the_two_signed_checkpoints(tmp_path, fake_witness):
    lines = _build_chain(tmp_path, 4)
    tampered = copy.deepcopy(lines)
    tampered[2]["root"] = "00" * 32  # forged/rolled-back tail, same as test_history_card.py's mutant

    from history_card import build_history_card

    card = build_history_card(node_id="node-a", log_id="log-a", checkpoint_lines=tampered, since_size=0)
    hist = history_cell(card)
    cont = continuity_cell(card, tampered)

    assert hist["state"] == CELL_FAILED
    assert cont["state"] == CELL_FAILED
    assert cont["text"].startswith("broken at ")
    # the two signed checkpoints either side of the break
    assert cont["last_good_checkpoint"]["mmr_size"] == lines[1]["mmr_size"]
    assert cont["last_good_checkpoint"]["signed"] is True
    assert cont["broken_checkpoint"]["mmr_size"] == lines[2]["mmr_size"]
    assert cont["broken_checkpoint"]["signed"] is True
    assert render_cell_text(cont)  # never blank


def test_witnessed_cell_true_when_the_covered_chain_has_a_witness(tmp_path, fake_witness):
    lines = _build_chain(tmp_path, 2)
    from history_card import build_history_card

    card = build_history_card(node_id="node-a", log_id="log-a", checkpoint_lines=lines, since_size=0)
    cell = witnessed_cell(card)

    assert cell["state"] == CELL_VERIFIED
    assert cell["witnesses"] == ["https://fake-ts.example"]


def test_witnessed_cell_absent_never_fabricated_with_no_checkpoints():
    from history_card import build_history_card

    card = build_history_card(node_id="node-a", log_id="log-a", checkpoint_lines=[], since_size=0)
    cell = witnessed_cell(card)

    assert cell["state"] == CELL_ABSENT
    assert cell["witnesses"] == []


# ---------------------------------------------------------------------------
# asked_cell -- refusal / absence / pending, never blank
# ---------------------------------------------------------------------------


def test_asked_cell_absent_by_default_names_the_real_current_gap():
    cell = asked_cell(None)

    assert cell["state"] == CELL_ABSENT
    assert cell["text"] == ASKED_ABSENT_REASON
    assert render_cell_text(cell) == ASKED_ABSENT_REASON
    # the stale pre-merge framing must be gone, not just renamed
    assert "capsule-emit #148" not in cell["text"]


def test_asked_cell_renders_a_signed_refusal_never_blank():
    requests = [
        {
            "request": {"subject": "full_history"},
            "response": {"status": "refused", "reason": "coverage_unsatisfiable", "sig": "abc123"},
        }
    ]

    cell = asked_cell(requests)

    assert cell["state"] == CELL_REFUSED
    assert cell["text"] == "card refused: coverage_unsatisfiable"
    assert cell["signed"] is True
    assert render_cell_text(cell) == "card refused: coverage_unsatisfiable"


def test_asked_cell_refusal_with_no_reason_still_never_blank():
    requests = [{"request": {}, "response": {"status": "refused", "sig": "abc"}}]

    cell = asked_cell(requests)

    assert cell["text"] == "card refused: no reason given"
    assert render_cell_text(cell)


def test_asked_cell_absence_names_transport_and_timeout():
    requests = [{"request": {}, "response": {"status": "no_answer", "transport": "nostr", "timeout_seconds": 30}}]

    cell = asked_cell(requests)

    assert cell["state"] == CELL_ABSENT
    assert cell["text"] == "no answer within 30s over nostr"


def test_asked_cell_ok_response_present():
    requests = [{"request": {}, "response": {"status": "ok"}}]

    cell = asked_cell(requests)

    assert cell["state"] == CELL_PRESENT
    assert "1 evidence-request(s) answered" == cell["text"]


# ---------------------------------------------------------------------------
# peer_history_cell / served_cell -- v2 "either wired or pending", never a
# stale reason and never the old my-card-as-theirs shortcut
# ---------------------------------------------------------------------------


def test_peer_history_cell_is_pending_and_carries_mine_for_reference(tmp_path, fake_witness):
    lines = _build_chain(tmp_path, 2)
    from history_card import build_history_card

    card = build_history_card(node_id="node-a", log_id="log-a", checkpoint_lines=lines, since_size=0)
    cell = peer_history_cell(card, lines)

    assert cell["state"] == CELL_PENDING
    assert cell["text"] == THEIRS_HISTORY_PENDING_REASON
    assert cell["mine_for_reference"]["history"] == history_cell(card)
    assert cell["mine_for_reference"]["continuity"] == continuity_cell(card, lines)
    assert render_cell_text(cell)


def test_served_cell_is_pending_never_a_fabricated_count():
    cell = served_cell()
    assert cell["state"] == CELL_PENDING
    assert "served_summary/1" in cell["text"]
    assert "mine_for_reference" not in cell


def test_served_cell_carries_mine_for_reference_when_own_summary_supplied():
    own_summary = {"schema": "mesh-served-summary/1", "node_id": "n1"}
    cell = served_cell(own_summary)
    assert cell["state"] == CELL_PENDING
    assert cell["mine_for_reference"] == own_summary


# ---------------------------------------------------------------------------
# pair_cell -- real, folds capsule_exchange_tab.digest_match_grade per peer
# ---------------------------------------------------------------------------


def test_pair_cell_absent_when_records_carry_no_exchange_id():
    records = [_capsule(capsule_id="c1", timestamp="t")]
    cell = pair_cell(records, records)
    assert cell["state"] == CELL_ABSENT
    assert cell["verified"] == 0


def test_pair_cell_verified_when_both_halves_present_and_digests_agree():
    requester = _exchange_capsule(capsule_id="r1", role="requested", exchange_id="ex-1")
    provider = _exchange_capsule(capsule_id="p1", role="served", exchange_id="ex-1")
    all_records = [requester, provider]

    cell = pair_cell([requester], all_records)

    assert cell["state"] == CELL_VERIFIED
    assert cell["verified"] == 1
    assert cell["missing"] == 0
    assert cell["failed"] == 0


def test_pair_cell_mutant_a_digest_mismatch_flips_failed_never_verified():
    requester = _exchange_capsule(capsule_id="r1", role="requested", exchange_id="ex-1", response_digest="b" * 64)
    provider = _exchange_capsule(capsule_id="p1", role="served", exchange_id="ex-1", response_digest="c" * 64)
    all_records = [requester, provider]

    cell = pair_cell([requester], all_records)

    assert cell["state"] == CELL_FAILED
    assert cell["failed"] == 1
    assert cell["state"] != CELL_VERIFIED


def test_pair_cell_is_missing_not_verified_when_only_one_half_is_in_this_view():
    requester = _exchange_capsule(capsule_id="r1", role="requested", exchange_id="ex-1")

    cell = pair_cell([requester], [requester])

    assert cell["missing"] == 1
    assert cell["verified"] == 0
    assert cell["state"] != CELL_VERIFIED


# ---------------------------------------------------------------------------
# verdicts_cell -- real for self-sealed adjudications about this peer;
# references-path always pending
# ---------------------------------------------------------------------------


def _adjudication_capsule(*, capsule_id, half_a, half_b, verdict):
    return {
        "capsule_id": capsule_id,
        "model_attestation": {
            "compute_attestation": {
                "adjudication": {"verdict": verdict, "half_a_capsule_id": half_a, "half_b_capsule_id": half_b}
            }
        },
    }


def test_verdicts_cell_pending_when_nothing_sealed_about_this_peer():
    records = [_capsule(capsule_id="c1", timestamp="t")]
    cell = verdicts_cell(records, records)
    assert cell["state"] == CELL_PENDING
    assert cell["text"] == VERDICTS_REFERENCES_PENDING_REASON


def test_verdicts_cell_contradicted_never_folded_into_a_clean_pass():
    peer_records = [_capsule(capsule_id="peer-c1", timestamp="t")]
    adjudication = _adjudication_capsule(capsule_id="adj1", half_a="peer-c1", half_b="other", verdict="contradicted:owner-x")
    all_records = peer_records + [adjudication]

    cell = verdicts_cell(peer_records, all_records)

    assert cell["state"] == CELL_CONTRADICTED
    assert cell["tally"]["contradicted"] == 1
    assert cell["adjudication_capsule_id"] == "adj1"
    assert VERDICTS_REFERENCES_PENDING_REASON in cell["text"]


def test_verdicts_cell_never_counts_an_adjudication_about_a_different_peer():
    peer_records = [_capsule(capsule_id="peer-c1", timestamp="t")]
    unrelated = _adjudication_capsule(capsule_id="adj1", half_a="someone-else", half_b="another", verdict="corroborated")

    cell = verdicts_cell(peer_records, peer_records + [unrelated])

    assert cell["state"] == CELL_PENDING
    assert cell["tally"]["corroborated"] == 0


# ---------------------------------------------------------------------------
# role_and_count_cell -- direction of exchange, never a trust signal
# ---------------------------------------------------------------------------


def test_role_and_count_cell_both_directions():
    records = [
        _exchange_capsule(capsule_id="r1", role="requested", exchange_id="ex-1"),
        _exchange_capsule(capsule_id="p1", role="served", exchange_id="ex-2"),
    ]
    cell = role_and_count_cell(records)
    assert cell["role"] == "both"
    assert cell["you_to_them_count"] == 1
    assert cell["them_to_you_count"] == 1


def test_role_and_count_cell_one_direction_only():
    records = [_exchange_capsule(capsule_id="p1", role="served", exchange_id="ex-1")]
    cell = role_and_count_cell(records)
    assert cell["role"] == "them_to_you"
    assert cell["them_to_you_count"] == 1
    assert cell["you_to_them_count"] == 0


def test_render_cell_text_never_returns_blank_even_with_no_text_key():
    assert render_cell_text({"state": "absent"}) == "no evidence recorded"
    assert render_cell_text({}) == "no evidence recorded"


# ---------------------------------------------------------------------------
# sort_peer_rows -- any property, never trust
# ---------------------------------------------------------------------------


def test_sort_peer_rows_refuses_trust_shaped_keys():
    rows = [{"exchange_count": 1}]
    for bad_key in ("trust", "trust_score", "rating"):
        with pytest.raises(ValueError):
            sort_peer_rows(rows, bad_key)


def test_sort_peer_rows_sorts_by_any_other_property():
    rows = [
        {"peer_id": "b", "exchange_count": 5},
        {"peer_id": "a", "exchange_count": 1},
    ]

    by_count = sort_peer_rows(rows, "exchange_count")
    by_peer = sort_peer_rows(rows, "peer_id")

    assert [r["exchange_count"] for r in by_count] == [1, 5]
    assert [r["peer_id"] for r in by_peer] == ["a", "b"]


def test_sort_peer_rows_sorts_by_a_dict_valued_cell_via_its_text():
    rows = [
        {"peer_id": "b", "rung": {"text": "unilateral_fallback"}},
        {"peer_id": "a", "rung": {"text": "full_bilateral"}},
    ]

    sorted_rows = sort_peer_rows(rows, "rung")

    # alphabetical on the cell's own text -- "full_bilateral" < "unilateral_fallback"
    assert [r["peer_id"] for r in sorted_rows] == ["a", "b"]


# ---------------------------------------------------------------------------
# build_peer_row / build_peers_payload -- full assembly + no rating fields
# ---------------------------------------------------------------------------


def test_build_peers_payload_assembles_one_row_per_peer(tmp_path, fake_witness):
    lines = _build_chain(tmp_path, 3)
    records = [
        _capsule(capsule_id="a1", timestamp="2026-09-01T00:00:00Z", cross_party={"initiator_ref": "x" * 64}),
        _capsule(capsule_id="a2", timestamp="2026-09-02T00:00:00Z", cross_party={"initiator_ref": "x" * 64}),
        _capsule(capsule_id="b1", timestamp="2026-09-01T00:00:00Z", cross_party=None),
    ]

    payload = build_peers_payload(records, node_id="node-a", log_id="log-a", checkpoint_lines=lines)

    assert payload["peer_count"] == 2
    assert payload["default_sort"] == "last_seen"
    identified = next(r for r in payload["rows"] if r["peer_id"] is not None)
    unattributed = next(r for r in payload["rows"] if r["peer_id"] is None)
    assert identified["exchange_count"] == 2
    assert identified["first_seen"] == "2026-09-01T00:00:00Z"
    assert identified["last_seen"] == "2026-09-02T00:00:00Z"
    assert unattributed["node"]["state"] == CELL_ABSENT
    # every row shares the same node-level history facts, now folded into
    # the single (pending) "history (theirs)" cell's mine_for_reference
    assert identified["history"]["mine_for_reference"]["continuity"] == unattributed["history"]["mine_for_reference"]["continuity"]
    # default sort is most-recent first
    assert payload["rows"][0]["last_seen"] >= payload["rows"][-1]["last_seen"]
    # the 7 v2 columns, never the old 8
    for row in payload["rows"]:
        assert set(row) >= {"node", "rung", "role", "history", "served", "pair", "verdicts", "asked", "expand"}


def test_build_peers_payload_raises_on_a_smuggled_rating_field(monkeypatch):
    import peer_accountability_tab as mod

    def _poisoned_node_cell(peer_id, records):
        return {"state": CELL_PRESENT, "text": "x", "trust_score": 99}

    monkeypatch.setattr(mod, "node_cell", _poisoned_node_cell)

    records = [_capsule(capsule_id="a1", timestamp="t", cross_party={"initiator_ref": "x" * 64})]
    with pytest.raises(RatingFieldError):
        build_peers_payload(records, node_id="node-a", log_id="log-a", checkpoint_lines=[])


def test_assert_no_rating_fields_catches_every_forbidden_key():
    for key in FORBIDDEN_RATING_KEYS:
        with pytest.raises(RatingFieldError):
            assert_no_rating_fields({"outer": {key: 1}})


def test_assert_no_rating_fields_passes_clean_payloads():
    assert_no_rating_fields({"node": {"state": "present", "text": "peer-a"}, "rows": [{"a": 1}]})


# ---------------------------------------------------------------------------
# HTML shell embed invariant
# ---------------------------------------------------------------------------


def test_render_peers_tab_html_embeds_the_payload_exactly_once():
    payload = {"node_id": "node-a", "peer_count": 0, "rows": []}
    html = render_peers_tab_html(payload)
    assert 'window.__PEERS_PAYLOAD__ = {"node_id":"node-a","peer_count":0,"rows":[]};' in html


def test_render_peers_tab_html_escapes_hostile_lt_in_payload_values():
    payload = {"node_id": "node-a", "peer_count": 1, "rows": [{"peer_id": "<script>alert(1)</script>"}]}
    html = render_peers_tab_html(payload)
    assert "<script>alert" not in html
    assert "\\u003cscript>alert(1)\\u003c/script>" in html


# ---------------------------------------------------------------------------
# label_counterparty -- served_by_node_id peer extraction (the real-data gap)
# ---------------------------------------------------------------------------


def _served_capsule(*, capsule_id: str, served_by_node_id: str, timestamp: str = "2026-09-07T00:00:00Z", role: str = "served") -> dict:
    """Minimal capsule with a serving_provenance.served_by_node_id field,
    matching the shape the Rust plugin emits on the serving path."""
    return {
        "capsule_id": capsule_id,
        "operator": "op",
        "timestamp": timestamp,
        "model_attestation": {
            "model_id": "m",
            "compute_attestation": {
                "x-mesh-poc-v1": {
                    "role": role,
                    "serving_provenance": {
                        "served_by_node_id": served_by_node_id,
                        "requesting_party": "unknown",
                        "exchange_id": f"ex-{capsule_id}",
                        "dispatch_path": "raw_proxy",
                    },
                }
            },
        },
        "effect": {"request_digest": "a" * 64, "response_digest": "b" * 64, "effect_attestation": "gate_executed"},
        "disposition": {"decision": "accept", "verdict_class": "executed"},
    }


def _requested_capsule(*, capsule_id: str, served_by_node_id: str, timestamp: str = "2026-09-07T00:00:00Z") -> dict:
    """Capsule with role=requested and a remote served_by_node_id -- the
    shape a requestor-side sidecar record would carry."""
    cap = _served_capsule(capsule_id=capsule_id, served_by_node_id=served_by_node_id, timestamp=timestamp, role="requested")
    return cap


# ---

OWN_NODE_ID = "aaaa" * 16  # 64 hex chars
PEER_A_NODE_ID = "bbbb" * 16
PEER_B_NODE_ID = "cccc" * 16


def test_label_counterparty_served_by_own_node_is_unknown():
    """A record where served_by_node_id == own_node_id is not a peer -- it's
    this node's own serving record.  Must stay 'unknown'."""
    from capsule_mesh_view import label_counterparty

    cap = _served_capsule(capsule_id="c1", served_by_node_id=OWN_NODE_ID)
    assert label_counterparty(cap, OWN_NODE_ID) == "unknown"


def test_label_counterparty_served_by_peer_returns_peer_key():
    """A record where served_by_node_id differs from own_node_id is a peer's
    record in a cross-node combined ledger view -- must be identified."""
    from capsule_mesh_view import label_counterparty

    cap = _served_capsule(capsule_id="c1", served_by_node_id=PEER_A_NODE_ID)
    label = label_counterparty(cap, OWN_NODE_ID)
    assert label.startswith("node:")
    assert PEER_A_NODE_ID[:16] in label


def test_label_counterparty_role_requested_uses_served_by_as_peer():
    """When role=requested (this node sent the request), served_by_node_id
    is the REMOTE serving node -- a peer regardless of own_node_id."""
    from capsule_mesh_view import label_counterparty

    cap = _requested_capsule(capsule_id="c1", served_by_node_id=PEER_A_NODE_ID)
    label = label_counterparty(cap, OWN_NODE_ID)
    assert label.startswith("node:")
    assert PEER_A_NODE_ID[:16] in label


def test_label_counterparty_requesting_party_used_when_non_unknown():
    """serving_provenance.requesting_party is used as a peer id when it is
    a real node id (not 'unknown')."""
    from capsule_mesh_view import label_counterparty

    cap = _capsule(capsule_id="c1", timestamp="t")
    # inject a non-unknown requesting_party
    cap["model_attestation"]["compute_attestation"]["x-mesh-poc-v1"]["serving_provenance"] = {
        "served_by_node_id": OWN_NODE_ID,
        "requesting_party": PEER_A_NODE_ID,
    }
    label = label_counterparty(cap, OWN_NODE_ID)
    assert label.startswith("node:")
    assert PEER_A_NODE_ID[:16] in label


def test_group_by_peer_with_own_node_id_separates_peer_records():
    """group_by_peer with own_node_id extracts distinct peer buckets from
    a combined cross-node record set.  This is the gap that left the pane
    empty: without own_node_id, all records group under 'unknown'."""
    own_caps = [_served_capsule(capsule_id=f"own-{i}", served_by_node_id=OWN_NODE_ID, timestamp=f"2026-09-07T0{i}:00:00Z") for i in range(3)]
    peer_a_caps = [_served_capsule(capsule_id=f"pa-{i}", served_by_node_id=PEER_A_NODE_ID, timestamp=f"2026-09-07T0{i}:10:00Z") for i in range(2)]
    peer_b_caps = [_served_capsule(capsule_id=f"pb-{i}", served_by_node_id=PEER_B_NODE_ID, timestamp=f"2026-09-07T0{i}:20:00Z") for i in range(4)]

    groups = group_by_peer(own_caps + peer_a_caps + peer_b_caps, own_node_id=OWN_NODE_ID)

    peer_ids = set(groups.keys())
    # own records bucket under UNKNOWN_PEER (served_by_node_id == own)
    assert UNKNOWN_PEER in peer_ids
    assert len(groups[UNKNOWN_PEER]) == 3
    # peer A and peer B each get their own bucket
    peer_keys = {k for k in peer_ids if k != UNKNOWN_PEER}
    assert len(peer_keys) == 2
    for k in peer_keys:
        assert k.startswith("node:")
    # count check
    total_peer_records = sum(len(v) for k, v in groups.items() if k != UNKNOWN_PEER)
    assert total_peer_records == 6  # 2 + 4


def test_group_by_peer_without_own_node_id_all_served_records_are_unknown():
    """Without own_node_id, all served records (requesting_party=unknown,
    no cross_party) fall into the 'unknown' bucket -- the PRE-FIX behaviour
    that left the pane empty when the sidecar didn't pass its node_id."""
    caps = [_served_capsule(capsule_id=f"c{i}", served_by_node_id=PEER_A_NODE_ID) for i in range(3)]

    groups = group_by_peer(caps)  # no own_node_id

    assert list(groups.keys()) == [UNKNOWN_PEER]
    assert len(groups[UNKNOWN_PEER]) == 3


def test_build_peers_payload_shows_distinct_peer_rows_from_cross_node_records(tmp_path, fake_witness):
    """build_peers_payload returns MORE THAN ONE peer row (not just the
    UNKNOWN_PEER bucket) when given combined cross-node records.  This is the
    end-to-end assertion the task requires: the Peers pane shows the nodes."""
    lines = _build_chain(tmp_path, 2)

    own_caps = [_served_capsule(capsule_id=f"own-{i}", served_by_node_id=OWN_NODE_ID, timestamp=f"2026-09-07T00:0{i}:00Z") for i in range(5)]
    peer_a_caps = [_served_capsule(capsule_id=f"pa-{i}", served_by_node_id=PEER_A_NODE_ID, timestamp=f"2026-09-07T01:0{i}:00Z") for i in range(3)]
    peer_b_caps = [_served_capsule(capsule_id=f"pb-{i}", served_by_node_id=PEER_B_NODE_ID, timestamp=f"2026-09-07T02:0{i}:00Z") for i in range(4)]

    payload = build_peers_payload(
        own_caps + peer_a_caps + peer_b_caps,
        node_id=OWN_NODE_ID,
        log_id="log-test",
        checkpoint_lines=lines,
    )

    assert payload["peer_count"] > 1, "must have more than one peer row -- not just the unknown bucket"
    # two identified peers
    identified = [r for r in payload["rows"] if r["peer_id"] is not None]
    assert len(identified) == 2
    # all identified peers have real node keys (not None)
    for row in identified:
        assert row["peer_id"] is not None
        assert row["peer_id"].startswith("node:")
        # honest pending cells -- history/served/verdicts are not_checked, never fabricated
        assert row["history"]["state"] == CELL_PENDING
        assert row["served"]["state"] == CELL_PENDING


# ---------------------------------------------------------------------------
# Real cross-node fixture ledger (full-ledgers-3node-20260907)
# ---------------------------------------------------------------------------


import pathlib

_FIXTURE_DIR = pathlib.Path(
    "/Users/intangible/dev/asg/_work/mesh-live-run-2026-09-06/out/full-ledgers-3node-20260907"
)
_GCP_A_NODE_ID = "781419308be2123b1884a5dba24dec0ffc5a2d59148eb312ea82ef1c7e0ff4ae"
_GCP_B_NODE_ID = "c814d483196404b7c6aea71f24edec0233c3442b7799338e90853f204307ed5a"
_M4_NODE_ID = "d534fb999c0fc6e38368103ceaaeb3393df3b21315c4dae91ac8cb666000149d"


def _read_jsonl_fixture(name: str) -> list[dict]:
    path = _FIXTURE_DIR / name
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


@pytest.mark.skipif(
    not _FIXTURE_DIR.exists(),
    reason="cross-node fixture ledger not present at expected path",
)
def test_cross_node_fixture_gcp_a_sees_gcp_b_as_peer():
    """Against the real 3-node capture ledger: GCP-A combined with GCP-B
    records should yield at least ONE identified peer row with GCP-B's
    actual node key -- the check the task requires."""
    records = _read_jsonl_fixture("GCP-A.jsonl") + _read_jsonl_fixture("GCP-B.jsonl")
    assert records, "fixture records must be non-empty"

    payload = build_peers_payload(
        records,
        node_id=_GCP_A_NODE_ID,
        log_id="GCP-A-crossnode",
        checkpoint_lines=[],
    )

    assert payload["peer_count"] > 1, f"expected >1 peer rows, got {payload['peer_count']}"
    identified = [r for r in payload["rows"] if r["peer_id"] is not None]
    assert len(identified) >= 1, "at least one identified peer row (not just UNKNOWN_PEER)"
    peer_ids = {r["peer_id"] for r in identified}
    # GCP-B's node id must appear as a peer key
    assert any(_GCP_B_NODE_ID[:16] in pid for pid in peer_ids), (
        f"GCP-B node key not found in peer_ids={peer_ids}"
    )
    # all identified peer rows must have honest NOT_CHECKED cells (pending, never fabricated)
    for row in identified:
        assert row["history"]["state"] == CELL_PENDING
        assert row["served"]["state"] == CELL_PENDING
        assert row["node"]["state"] == CELL_PRESENT


@pytest.mark.skipif(
    not _FIXTURE_DIR.exists(),
    reason="cross-node fixture ledger not present at expected path",
)
def test_cross_node_fixture_three_nodes_yields_two_peer_rows():
    """Against the real 3-node capture ledger (GCP-A + GCP-B + M4):
    from GCP-A's perspective, the other two nodes are peers -- the pane
    must show exactly two identified peer rows plus one UNKNOWN_PEER bucket
    (GCP-A's own served records that requested_party=unknown doesn't resolve)."""
    records = (
        _read_jsonl_fixture("GCP-A.jsonl")
        + _read_jsonl_fixture("GCP-B.jsonl")
        + _read_jsonl_fixture("M4.jsonl")
    )
    assert records, "fixture records must be non-empty"

    payload = build_peers_payload(
        records,
        node_id=_GCP_A_NODE_ID,
        log_id="GCP-A-3node",
        checkpoint_lines=[],
    )

    # At least 3 rows: 2 identified peers + 1 unknown bucket
    assert payload["peer_count"] >= 3, f"expected >=3 peer rows (2 peers + unknown), got {payload['peer_count']}"
    identified = [r for r in payload["rows"] if r["peer_id"] is not None]
    assert len(identified) >= 2, f"expected >=2 identified peers, got {len(identified)}"
    # Both known nodes must appear
    peer_ids = {r["peer_id"] for r in identified}
    assert any(_GCP_B_NODE_ID[:16] in pid for pid in peer_ids), "GCP-B must appear"
    assert any(_M4_NODE_ID[:16] in pid for pid in peer_ids), "M4 must appear"
