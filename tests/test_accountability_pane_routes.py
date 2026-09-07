# SPDX-License-Identifier: Apache-2.0
"""[mesh-live-tab-pane-proxy] L1 -- accountability_pane_routes.build_pane_a_json/
build_pane_b_json/build_pane_c_json, the JSON builders behind the sidecar's
GET /accountability/pane-a|b|c. Exercises them directly (no HTTP server) over
a real capsule_sidecar.NodeState + its real cll.ledger.store.LedgerStore --
the same node_state fixture shape tests/test_evidence_responder.py uses.

Alphabetically ahead of ``test_ask_history.py`` (and therefore also ahead of
``test_bilateral_demo.py``/``test_forwarded_copy_and_keys.py``/
``test_replay_spot_check.py``, the three files that stub ``model_identity``
at collection time and whose OWN tests depend on that stub staying in place
-- see ``tests/conftest.py``'s note). Since THIS file collects first and
imports ``capsule_sidecar`` for real, it must install the SAME stub itself
before doing so -- otherwise it would import the real ``model_identity``
first and permanently deny those three files their stub for the rest of the
process (same idiom as ``test_ask_history.py``'s top matter).
"""
from __future__ import annotations

import json
import sys
import types

_stubbed_model_identity = "model_identity" not in sys.modules
if _stubbed_model_identity:
    sys.modules["model_identity"] = types.ModuleType("model_identity")
    sys.modules["model_identity"].load_manifest = lambda p: {}
    sys.modules["model_identity"].model_package_digest = lambda m: ""

import pytest

import accountability_pane_routes as routes
import capsule_sidecar as cs
from self_accountability import RatingFieldError


@pytest.fixture
def node_state(tmp_path):
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps({"model_id": "m/1", "source_model": {"sha256": "e" * 64, "canonical_ref": "m/1"}, "skippy_abi_version": "1"})
    )
    checkpoint_config_path = tmp_path / "checkpoint.toml"
    checkpoint_config_path.write_text('[checkpoint]\nlog_id = "test-node"\ncadence_entries = 1\n')
    state = cs.default_state(
        ledger_dir=tmp_path / "ledger",
        manifest_path=manifest_path,
        keys_dir=tmp_path / "keys",
        runtime_label="test-runtime",
        runtime_digest="deadbeef" * 8,
        checkpoint_config_path=checkpoint_config_path,
    )
    return state


def _mesh_capsule(*, capsule_id: str, exchange_id: str, timestamp: str, served_by: str = "node-self") -> dict:
    return {
        "spec_version": "draft-mih-scitt-agent-action-capsule-02",
        "format_version": "2",
        "capsule_id": capsule_id,
        "operator": "op",
        "timestamp": timestamp,
        "model_attestation": {
            "model_id": "meta-llama/Llama-3.2-3B-Instruct",
            "compute_attestation": {
                "x-mesh-poc-v1": {
                    "client_nonce_source": "client_supplied",
                    "serving_provenance": {
                        "model": {"canonical_ref": "meta-llama/Llama-3.2-3B-Instruct", "architecture": "llama"},
                        "hardware": {"gpu": "Apple M4 Max", "is_soc": True},
                        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
                        "served_by_node_id": served_by,
                        "exchange_id": exchange_id,
                    },
                    "evidence_refs": {"binary_attestation": None, "tee_attestation": None, "trace_citation": None},
                }
            },
        },
        "effect": {"request_digest": "1" * 64, "response_digest": "2" * 64, "effect_attestation": "gate_executed"},
        "disposition": {"decision": "accept", "verdict_class": "executed"},
    }


def _seed(state, n: int) -> list[dict]:
    capsules = [
        _mesh_capsule(capsule_id=f"{i:064x}", exchange_id=f"exch-{i:03d}", timestamp=f"2026-09-0{1 + i % 8}T00:00:00Z")
        for i in range(n)
    ]
    for cap in capsules:
        state.log_source.append(cap)
    return capsules


# ---------------------------------------------------------------------------
# Pane A
# ---------------------------------------------------------------------------


def test_pane_a_json_over_empty_ledger_never_crashes(node_state):
    payload = routes.build_pane_a_json(node_state)
    assert payload["rows"] == []


def test_pane_a_json_reflects_seeded_records(node_state):
    capsules = _seed(node_state, 3)
    payload = routes.build_pane_a_json(node_state)
    assert len(payload["rows"]) == len(capsules)
    assert payload["card"] is not None  # node_id/log_id were supplied -- never a fabricated empty face
    assert payload["operator"] == node_state.operator


def test_pane_a_json_passes_no_rating_fields(node_state, monkeypatch):
    _seed(node_state, 2)
    monkeypatch.setattr(routes, "assert_no_rating_fields", _raise := (lambda *_a, **_kw: (_ for _ in ()).throw(RatingFieldError("boom"))))
    with pytest.raises(RatingFieldError):
        routes.build_pane_a_json(node_state)


def _find_state_values(value, out):
    if isinstance(value, dict):
        state = value.get("state")
        if isinstance(state, str):
            out.append(state)
        for sub in value.values():
            _find_state_values(sub, out)
    elif isinstance(value, list):
        for item in value:
            _find_state_values(item, out)


def test_pane_a_json_never_carries_the_retired_pending_stub_state(node_state):
    """[mesh-live-tab-pane-proxy] L2: Pane A's ``references``/``absences_
    recorded_against_me``/``refusals_issued``/``native_log_join`` blocks
    used to carry the ad hoc ``"pending"`` string for a mechanism that does
    not exist in this repo yet -- ``capsule_accountability_tab.
    BLOCK_PENDING`` now aliases ``assurance_map.STATE_NOT_CHECKED``, same
    migration ``peer_accountability_tab.CELL_PENDING`` already did. This
    walks every ``state`` key in a real ``build_pane_a_json`` payload
    (seeded, so the adjudications-received/served-summary/footer blocks are
    all populated, not just the empty-ledger defaults) and asserts the
    retired literal never appears as a *state value* -- prose explaining
    the gap (e.g. ``REFERENCES_PENDING_REASON``'s text) is a separate,
    allowed surface, and ``"present-unverified"`` is untouched, in-scope-
    elsewhere vocabulary for the mature ladder-graded rungs
    (freshness/cross-party/measurement-class), not a retired stub state."""
    _seed(node_state, 2)
    payload = routes.build_pane_a_json(node_state)
    states = []
    _find_state_values(payload, states)
    assert "pending" not in states


# ---------------------------------------------------------------------------
# Pane B
# ---------------------------------------------------------------------------


def test_pane_b_json_over_empty_ledger_never_crashes(node_state):
    payload = routes.build_pane_b_json(node_state)
    assert payload["rows"] == []
    assert payload["peer_count"] == 0


def test_pane_b_json_groups_by_peer(node_state):
    _seed(node_state, 4)
    payload = routes.build_pane_b_json(node_state)
    # every seeded record shares served_by="node-self" (this node itself,
    # not a distinct peer) -- group_by_peer's own rules decide whether that
    # surfaces as a row; this just proves the builder ran over every record
    # without crashing and returned the shape Pane B always returns.
    assert "rows" in payload and "peer_count" in payload
    assert payload["default_sort"] == "last_seen"


# ---------------------------------------------------------------------------
# Pane C
# ---------------------------------------------------------------------------


def test_pane_c_list_over_empty_ledger_never_crashes(node_state):
    payload = routes.build_pane_c_json(node_state)
    assert payload["rows"] == []
    assert payload["next_after_seq"] is None
    assert payload["archived_segments"] == []


def test_pane_c_list_reflects_seeded_records_uncapped(node_state):
    capsules = _seed(node_state, 5)
    payload = routes.build_pane_c_json(node_state, limit=None)
    assert payload["row_count"] == len(capsules)
    assert payload["next_after_seq"] is None


def test_pane_c_list_respects_cap_and_pages_through_everything(node_state):
    capsules = _seed(node_state, 7)
    seen_keys: set[str] = set()
    after_seq = 0
    pages = 0
    while True:
        pages += 1
        assert pages < 100, "runaway pagination"
        payload = routes.build_pane_c_json(node_state, limit=3, after_seq=after_seq)
        assert len(payload["rows"]) <= 3
        seen_keys.update(row["exchange_key"] for row in payload["rows"])
        if payload["next_after_seq"] is None:
            break
        after_seq = payload["next_after_seq"]
    assert seen_keys == {f"exch-{i:03d}" for i in range(len(capsules))}


def test_pane_c_drilldown_finds_a_seeded_exchange(node_state):
    capsules = _seed(node_state, 3)
    target = capsules[1]
    exchange_id = target["model_attestation"]["compute_attestation"]["x-mesh-poc-v1"]["serving_provenance"]["exchange_id"]

    payload = routes.build_pane_c_json(node_state, exchange_id=exchange_id)

    assert payload["found"] is True
    assert payload["view"]["capsule_id"] == target["capsule_id"]


def test_pane_c_drilldown_unknown_exchange_id_is_honestly_not_found(node_state):
    _seed(node_state, 2)
    payload = routes.build_pane_c_json(node_state, exchange_id="exch-does-not-exist")
    assert payload == {"exchange_key": "exch-does-not-exist", "found": False}


def test_pane_c_drilldown_never_relies_on_the_page_cap(node_state):
    """The regression this guards: a drill-down for a record past a small
    page window must still be found -- it reads the whole ledger, not a
    capped page (see the module docstring's reasoning)."""
    capsules = _seed(node_state, 10)
    last = capsules[-1]
    exchange_id = last["model_attestation"]["compute_attestation"]["x-mesh-poc-v1"]["serving_provenance"]["exchange_id"]

    # limit/after_seq are list-mode-only kwargs; drilldown ignores them
    # entirely once exchange_id is supplied (asserted by still finding a
    # record that a limit=1 page would never include).
    payload = routes.build_pane_c_json(node_state, exchange_id=exchange_id, limit=1, after_seq=0)

    assert payload["found"] is True
    assert payload["view"]["capsule_id"] == last["capsule_id"]
