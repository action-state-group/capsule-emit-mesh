# SPDX-License-Identifier: Apache-2.0
"""[mesh-live-tab-pane-proxy] L0 -- cap/paging over ``read_capsules_page``,
for both the flat-file fallback and the segmented ``LedgerStore``. The
sidecar's future pane routes call this per HTTP request; a page must never
exceed its cap, and the cursor must round-trip every record exactly once
across pages -- the two properties these tests exist to pin down.
"""
from __future__ import annotations

import json
from pathlib import Path

from ledger_store_backend import (
    ARCHIVED_SEGMENT_KIND,
    open_ledger_store,
    read_all_capsules,
    read_capsules_page,
)


def _write_flat_ledger(ledger_dir: Path, n: int) -> list[dict]:
    ledger_dir.mkdir(parents=True, exist_ok=True)
    capsules = [{"capsule_id": f"{i:064x}", "n": i} for i in range(n)]
    with (ledger_dir / "capsules.jsonl").open("w", encoding="utf-8") as fh:
        for cap in capsules:
            fh.write(json.dumps(cap) + "\n")
    return capsules


def _collect_all_pages(ledger_dir: Path, *, limit: int) -> tuple[list[dict], list[dict]]:
    records: list[dict] = []
    archived_seen: list[dict] = []
    after_seq = 0
    pages = 0
    while True:
        pages += 1
        assert pages < 1000, "runaway pagination loop -- cursor never reached None"
        page_records, archived, next_after_seq = read_capsules_page(ledger_dir, limit=limit, after_seq=after_seq)
        assert len(page_records) <= limit, "a page exceeded its own cap"
        records.extend(page_records)
        archived_seen.extend(archived)
        if next_after_seq is None:
            break
        after_seq = next_after_seq
    return records, archived_seen


def test_flat_ledger_uncapped_matches_read_all_capsules(tmp_path: Path) -> None:
    ledger_dir = tmp_path / "flat"
    capsules = _write_flat_ledger(ledger_dir, 5)

    records, archived, next_after_seq = read_capsules_page(ledger_dir)
    assert records == capsules
    assert archived == []
    assert next_after_seq is None

    all_records, all_archived = read_all_capsules(ledger_dir)
    assert (all_records, all_archived) == (records, archived)


def test_flat_ledger_paging_round_trips_every_record_once(tmp_path: Path) -> None:
    ledger_dir = tmp_path / "flat"
    capsules = _write_flat_ledger(ledger_dir, 7)

    records, archived = _collect_all_pages(ledger_dir, limit=3)
    assert records == capsules
    assert archived == []


def test_flat_ledger_cap_exactly_at_end_reports_no_next_page(tmp_path: Path) -> None:
    ledger_dir = tmp_path / "flat"
    capsules = _write_flat_ledger(ledger_dir, 4)

    records, archived, next_after_seq = read_capsules_page(ledger_dir, limit=4, after_seq=0)
    assert records == capsules
    assert next_after_seq is None, "cap landing exactly on the last record must not imply a next page"


def test_flat_ledger_empty_dir_returns_empty_page(tmp_path: Path) -> None:
    ledger_dir = tmp_path / "empty"
    ledger_dir.mkdir()
    records, archived, next_after_seq = read_capsules_page(ledger_dir, limit=10)
    assert records == []
    assert archived == []
    assert next_after_seq is None


def _build_rotating_store(tmp_path: Path, *, n: int) -> tuple[Path, list[dict]]:
    from cll.checkpoint.emit import Signer as _SignerProtocol  # noqa: F401 -- documents the shape
    from cll.checkpoint.index import MmrLedger
    from cll.ledger.segments import MmrCheckpointer

    ledger_dir = tmp_path / "rotating"
    store = open_ledger_store(ledger_dir, log_id="paging-test")
    store._max_segment_bytes = 200  # force rotation almost immediately, deterministically

    class _FixedSigner:
        key_id = "00" * 32

        def sign(self, digest_hex: str) -> str:
            return "00" * 64

    mmr = MmrLedger(store)
    store.set_checkpointer(MmrCheckpointer(mmr=mmr, signer=_FixedSigner(), log_id="paging-test"))

    capsules = [{"capsule_id": f"{i:064x}", "n": i, "payload": "x" * 40} for i in range(n)]
    for cap in capsules:
        store.append(cap)

    segments = store.list_segments()
    assert len(segments) >= 2, "expected at least one rotation to have fired"
    store.close()
    return ledger_dir, capsules


def test_store_ledger_paging_round_trips_every_record_once(tmp_path: Path) -> None:
    ledger_dir, capsules = _build_rotating_store(tmp_path, n=30)

    records, archived = _collect_all_pages(ledger_dir, limit=7)
    assert records == capsules
    assert archived == []


def test_store_ledger_cap_never_exceeded_across_an_unmounted_segment(tmp_path: Path) -> None:
    ledger_dir, capsules = _build_rotating_store(tmp_path, n=30)

    store = open_ledger_store(ledger_dir, log_id="paging-test")
    closed = [s for s in store.list_segments() if s.manifest is not None]
    assert closed
    to_unmount = closed[0]
    store.unmount_segment(to_unmount.name)
    store.close()

    records, archived = _collect_all_pages(ledger_dir, limit=5)
    assert any(a["segment"] == to_unmount.name for a in archived)
    unmounted_entry = next(a for a in archived if a["segment"] == to_unmount.name)
    assert unmounted_entry["kind"] == ARCHIVED_SEGMENT_KIND

    total_visible = len(records) + sum(a["record_count"] for a in archived if a["segment"] == to_unmount.name)
    # every page reported the same archived-segment gap (paging doesn't dedupe
    # across calls) -- collapse to the distinct segment names to compare counts.
    distinct_archived_records = sum(
        a["record_count"] for a in {a["segment"]: a for a in archived}.values()
    )
    assert len(records) + distinct_archived_records == len(capsules)
    assert total_visible <= len(capsules)


def test_store_ledger_uncapped_matches_read_all_capsules(tmp_path: Path) -> None:
    ledger_dir, capsules = _build_rotating_store(tmp_path, n=12)

    records, archived, next_after_seq = read_capsules_page(ledger_dir)
    assert records == capsules
    assert archived == []
    assert next_after_seq is None

    all_records, all_archived = read_all_capsules(ledger_dir)
    assert (all_records, all_archived) == (records, archived)
