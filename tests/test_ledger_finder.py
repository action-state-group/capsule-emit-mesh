# SPDX-License-Identifier: Apache-2.0
"""[mesh-ui-ledger-finder] The Accountability page's Finder: query bar
(time range / exchange id / capsule id / digest / peer) over
``ledger_store_backend.read_all_capsules``, results wired straight into the
existing Pane C drawer (``capsule_exchange_tab.build_exchange_view`` /
``render_exchange_subtab_html``).

Covers this task's own acceptance line: a Finder id hit is the same record
the CLI ``ledger show <id>`` returns; a time-range query on a rotated
ledger spans mounted segments; an unmounted segment renders "archived --
mount to view" with a date range; results actually build a Pane C view
without crashing.
"""
from __future__ import annotations

import io
import shutil
from pathlib import Path

import pytest
from capsule_emit.checkpoint import MmrLedger
from capsule_emit.ledger import show
from cll.ledger.segments import MmrCheckpointer

from ledger_finder import (
    capsule_matches_id,
    find_capsules,
    peer_for,
    render_archived_segments_html,
    render_finder_page_html,
)
from ledger_store_backend import import_flat_ledger_once, materialize_flat_view, open_ledger_store

REPO_ROOT = Path(__file__).parent.parent
REAL_DEMO_LEDGERS = ["ledger-checkpoint-demo", "ledger-real-deployment"]


def _copy_fixture(name: str, tmp_path: Path) -> Path:
    dest = tmp_path / name
    shutil.copytree(REPO_ROOT / name, dest)
    return dest


class _FixedSigner:
    key_id = "00" * 32

    def sign(self, digest_hex: str) -> str:
        return "00" * 64


def _build_rotating_ledger(ledger_dir: Path, *, capsule_count: int = 30) -> tuple[list[dict], object]:
    """A store with >=2 segments, timestamps spread across three days so a
    time-range query has something real to span. Mirrors
    ``test_ledger_store_migration_invariance.py``'s own rotation fixture."""
    store = open_ledger_store(ledger_dir, log_id="finder-rotation-test")
    store._max_segment_bytes = 200  # force rotation almost immediately, deterministically

    mmr = MmrLedger(store)
    store.set_checkpointer(MmrCheckpointer(mmr=mmr, signer=_FixedSigner(), log_id="finder-rotation-test"))

    capsules = [
        {
            "capsule_id": f"{i:064x}",
            "n": i,
            "timestamp": f"2026-09-{1 + i // 10:02d}T00:00:{i % 60:02d}Z",
            "payload": "x" * 40,
        }
        for i in range(capsule_count)
    ]
    for cap in capsules:
        store.append(cap)
    return capsules, store


# ── parity with the CLI `ledger show <id>` ─────────────────────────────────


@pytest.mark.parametrize("demo_name", REAL_DEMO_LEDGERS)
def test_id_query_returns_the_same_record_ledger_show_returns(demo_name: str, tmp_path: Path) -> None:
    ledger_dir = _copy_fixture(demo_name, tmp_path)
    store = open_ledger_store(ledger_dir, log_id=f"{demo_name}-finder-parity")
    try:
        import_flat_ledger_once(ledger_dir, store)
    finally:
        store.close()

    baseline = find_capsules(ledger_dir)
    target = baseline["all_records"][0]
    prefix = target["capsule_id"][:10]

    # `show()` is handed `materialize_flat_view`'s bridge output, not the
    # store dir directly: capsule-emit's OWN store-awareness (PR #156)
    # merged to its main but is not yet in a released package version, and
    # this repo deliberately did not bump its pinned floor for it (see
    # [mesh-ledger-store-migration]'s closure notes) -- exactly the
    # situation `materialize_flat_view` exists to bridge, independent of
    # which capsule-emit version is actually installed.
    out = io.StringIO()
    found = show(materialize_flat_view(ledger_dir), prefix, out=out)
    assert found is True
    cli_text = out.getvalue()
    assert target["capsule_id"] in cli_text

    result = find_capsules(ledger_dir, id_query=prefix)
    assert len(result["results"]) == 1
    assert result["results"][0] == target
    assert result["results"][0]["capsule_id"] == target["capsule_id"]


def test_id_query_exact_full_id_also_matches() -> None:
    ledger_dir = REPO_ROOT / "ledger-checkpoint-demo"
    baseline = find_capsules(ledger_dir)
    target = baseline["all_records"][0]
    result = find_capsules(ledger_dir, id_query=target["capsule_id"])
    assert [r["capsule_id"] for r in result["results"]] == [target["capsule_id"]]


def test_id_query_not_found_flags_maybe_archived_when_segments_are_unmounted(tmp_path: Path) -> None:
    ledger_dir = tmp_path / "rotating"
    _capsules, store = _build_rotating_ledger(ledger_dir)
    segments = store.list_segments()
    closed = [s for s in segments if s.manifest is not None]
    assert closed
    store.unmount_segment(closed[0].name)
    store.close()

    result = find_capsules(ledger_dir, id_query="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
    assert result["results"] == []
    assert result["not_found_but_maybe_archived"] is True
    assert len(result["archived_segments"]) == 1


def test_id_query_not_found_no_archived_segments_is_a_plain_miss() -> None:
    ledger_dir = REPO_ROOT / "ledger-checkpoint-demo"
    result = find_capsules(ledger_dir, id_query="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
    assert result["results"] == []
    assert result["not_found_but_maybe_archived"] is False
    assert result["archived_segments"] == []


def test_capsule_matches_id_is_exact_or_prefix() -> None:
    record = {"capsule_id": "abcdef0123456789"}
    assert capsule_matches_id(record, "abcdef0123456789")
    assert capsule_matches_id(record, "abcdef01")
    assert not capsule_matches_id(record, "zzz")


# ── time-range query spans rotated segments, archived segments labeled ────


def test_time_range_query_spans_mounted_segments_and_labels_the_archived_one(tmp_path: Path) -> None:
    ledger_dir = tmp_path / "rotating"
    capsules, store = _build_rotating_ledger(ledger_dir)
    segments = store.list_segments()
    closed = [s for s in segments if s.manifest is not None]
    assert len(closed) >= 1, "expected at least one rotation to have fired"
    to_unmount = closed[0]
    store.unmount_segment(to_unmount.name)
    store.close()

    result = find_capsules(ledger_dir, start="2026-09-01T00:00:00Z", end="2026-09-03T23:59:59Z")

    # Every capsule outside the unmounted segment is still found -- the query
    # spans every OTHER mounted segment, never stopping at the first gap.
    visible_count = len(result["results"])
    assert visible_count > 0
    assert visible_count < len(capsules)  # the unmounted segment's records are excluded from `results`

    assert len(result["archived_segments"]) == 1
    archived = result["archived_segments"][0]
    assert archived["segment"] == to_unmount.name
    assert archived["note"] == "archived -- mount to view"
    assert archived["first_ts"] is not None
    assert archived["last_ts"] is not None
    assert archived["first_ts"] <= archived["last_ts"]

    # visible + archived record_count reconstructs the whole ledger -- nothing
    # silently vanished, it's just not open for reading.
    assert visible_count + archived["record_count"] == len(capsules)


def test_mounting_the_segment_back_makes_it_visible_to_the_same_query(tmp_path: Path) -> None:
    ledger_dir = tmp_path / "rotating"
    capsules, store = _build_rotating_ledger(ledger_dir)
    segments = store.list_segments()
    to_unmount = next(s for s in segments if s.manifest is not None)
    store.unmount_segment(to_unmount.name)
    store.close()

    before = find_capsules(ledger_dir, start="2026-09-01T00:00:00Z", end="2026-09-03T23:59:59Z")
    assert len(before["archived_segments"]) == 1

    store2 = open_ledger_store(ledger_dir, log_id="finder-rotation-test")
    store2.mount_segment(to_unmount.name)
    store2.close()

    after = find_capsules(ledger_dir, start="2026-09-01T00:00:00Z", end="2026-09-03T23:59:59Z")
    assert after["archived_segments"] == []
    assert len(after["results"]) == len(capsules)


# ── peer / exchange_id filters (Python-level, not the SQL correlation index --
#    see ledger_finder.py's module docstring for why) ──────────────────────


def _mesh_capsule(*, capsule_id: str, timestamp: str, exchange_id: str, served_by: str | None, requesting: str | None) -> dict:
    return {
        "capsule_id": capsule_id,
        "timestamp": timestamp,
        "model_attestation": {
            "compute_attestation": {
                "x-mesh-poc-v1": {
                    "serving_provenance": {
                        "exchange_id": exchange_id,
                        "served_by_node_id": served_by,
                        "requesting_party": requesting,
                    }
                }
            }
        },
    }


def test_peer_for_reads_both_serving_provenance_identity_fields() -> None:
    record = _mesh_capsule(
        capsule_id="a" * 64, timestamp="2026-09-01T00:00:00Z", exchange_id="ex-1",
        served_by="node-alice", requesting="node-bob",
    )
    assert peer_for(record) == ("node-alice", "node-bob")


def test_exchange_id_and_peer_filters(tmp_path: Path) -> None:
    ledger_dir = tmp_path / "mesh-ledger"
    store = open_ledger_store(ledger_dir, log_id="finder-mesh-test")
    try:
        store.append(_mesh_capsule(capsule_id="a" * 64, timestamp="2026-09-01T00:00:00Z", exchange_id="ex-1", served_by="node-alice", requesting="node-bob"))
        store.append(_mesh_capsule(capsule_id="b" * 64, timestamp="2026-09-02T00:00:00Z", exchange_id="ex-2", served_by="node-carol", requesting="node-dave"))
    finally:
        store.close()

    by_exchange = find_capsules(ledger_dir, id_query="ex-1")
    assert [r["capsule_id"] for r in by_exchange["results"]] == ["a" * 64]

    by_peer_served = find_capsules(ledger_dir, peer="node-carol")
    assert [r["capsule_id"] for r in by_peer_served["results"]] == ["b" * 64]

    by_peer_requesting = find_capsules(ledger_dir, peer="node-bob")
    assert [r["capsule_id"] for r in by_peer_requesting["results"]] == ["a" * 64]

    by_peer_prefix = find_capsules(ledger_dir, peer="node-al")
    assert [r["capsule_id"] for r in by_peer_prefix["results"]] == ["a" * 64]


# ── a bar, not a pane: no filter means no results ──────────────────────────


def test_no_filters_returns_no_results_not_the_whole_ledger() -> None:
    ledger_dir = REPO_ROOT / "ledger-checkpoint-demo"
    result = find_capsules(ledger_dir)
    assert result["results"] == []
    assert result["all_records"]  # the ledger is non-empty; this isn't a broken read


# ── rendering: results open the Pane C drawer, archived segments render ───


def test_render_finder_page_embeds_the_pane_c_drawer_for_a_hit() -> None:
    ledger_dir = REPO_ROOT / "ledger-checkpoint-demo"
    baseline = find_capsules(ledger_dir)
    target = baseline["all_records"][0]
    result = find_capsules(ledger_dir, id_query=target["capsule_id"])
    html = render_finder_page_html(result)
    assert "finder-result" in html
    assert "exchange-card" in html  # capsule_exchange_tab.render_exchange_subtab_html's own class
    assert target["capsule_id"] in html


def test_render_finder_page_labels_archived_segments_with_date_range(tmp_path: Path) -> None:
    ledger_dir = tmp_path / "rotating"
    _capsules, store = _build_rotating_ledger(ledger_dir)
    to_unmount = next(s for s in store.list_segments() if s.manifest is not None)
    store.unmount_segment(to_unmount.name)
    store.close()

    result = find_capsules(ledger_dir, start="2026-09-01T00:00:00Z", end="2026-09-03T23:59:59Z")
    html = render_archived_segments_html(result["archived_segments"])
    assert "archived -- mount to view" in html
    assert "2026-09-0" in html  # the date range rendered, not just the note


def test_render_finder_page_reports_not_found_but_maybe_archived(tmp_path: Path) -> None:
    ledger_dir = tmp_path / "rotating"
    _capsules, store = _build_rotating_ledger(ledger_dir)
    to_unmount = next(s for s in store.list_segments() if s.manifest is not None)
    store.unmount_segment(to_unmount.name)
    store.close()

    result = find_capsules(ledger_dir, id_query="not-a-real-id")
    html = render_finder_page_html(result)
    assert "not found" in html
    assert "archived" in html
