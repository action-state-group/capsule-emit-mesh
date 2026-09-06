# SPDX-License-Identifier: Apache-2.0
"""[mesh-ledger-store-migration] THE gate: the MMR must not notice.

Recomputes EVERY historical checkpoint root from a `LedgerStore` imported
from a real, git-tracked demo ledger (`ledger-checkpoint-demo/`,
`ledger-real-deployment/` -- both produced by real runs, `checkpoints.jsonl`
entries included) and asserts byte-identical equality against the root
already persisted for that checkpoint. Any mismatch here means the
migration is not safe to ship -- "no close enough" (the task's own words).

Copies each fixture into `tmp_path` first -- `import_flat_ledger_once`
renames the source `capsules.jsonl` on success, and this test must never
mutate the committed fixtures.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from capsule_emit.checkpoint import CheckpointRecord, MmrLedger

from ledger_store_backend import (
    ARCHIVED_SEGMENT_KIND,
    import_flat_ledger_once,
    is_store_ledger,
    open_ledger_store,
    read_all_capsules,
)

REPO_ROOT = Path(__file__).parent.parent
REAL_DEMO_LEDGERS = ["ledger-checkpoint-demo", "ledger-real-deployment"]


def _copy_fixture(name: str, tmp_path: Path) -> Path:
    dest = tmp_path / name
    shutil.copytree(REPO_ROOT / name, dest)
    return dest


@pytest.mark.parametrize("demo_name", REAL_DEMO_LEDGERS)
def test_recomputed_checkpoint_roots_are_byte_identical(demo_name: str, tmp_path: Path) -> None:
    ledger_dir = _copy_fixture(demo_name, tmp_path)
    checkpoint_lines = [
        json.loads(line)
        for line in (ledger_dir / "checkpoints.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert checkpoint_lines, f"{demo_name} has no checkpoints -- nothing to prove invariance against"

    flat_capsule_lines = [
        line for line in (ledger_dir / "capsules.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()
    ]

    store = open_ledger_store(ledger_dir, log_id=f"{demo_name}-invariance")
    try:
        imported = import_flat_ledger_once(ledger_dir, store)
        assert imported == len(flat_capsule_lines)
        assert is_store_ledger(ledger_dir)
        assert not (ledger_dir / "capsules.jsonl").exists()  # renamed, never left ambiguous
        assert (ledger_dir / "capsules.jsonl.pre-store-migration").exists()

        mmr = MmrLedger(store)
        mmr.sync()
        assert mmr.leaf_count() == len(flat_capsule_lines)

        for cp_line in checkpoint_lines:
            cp_line = dict(cp_line)
            cp_line.pop("checkpoint_cose", None)  # sibling key, not part of CheckpointRecord's own shape
            cp = CheckpointRecord.from_dict(cp_line)
            recomputed_root = mmr.root_at(cp.mmr_size).hex()
            assert recomputed_root == cp.root, (
                f"{demo_name} checkpoint mmr_size={cp.mmr_size}: stored root {cp.root} != "
                f"recomputed {recomputed_root} -- THE gate failed, migration is not safe"
            )
    finally:
        store.close()


@pytest.mark.parametrize("demo_name", REAL_DEMO_LEDGERS)
def test_read_all_capsules_matches_flat_read_before_and_after_migration(demo_name: str, tmp_path: Path) -> None:
    ledger_dir = _copy_fixture(demo_name, tmp_path)
    flat_records = [
        json.loads(line) for line in (ledger_dir / "capsules.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()
    ]

    before_records, before_archived = read_all_capsules(ledger_dir)
    assert before_records == flat_records
    assert before_archived == []

    store = open_ledger_store(ledger_dir, log_id=f"{demo_name}-read")
    try:
        import_flat_ledger_once(ledger_dir, store)
    finally:
        store.close()

    after_records, after_archived = read_all_capsules(ledger_dir)
    assert after_records == flat_records
    assert after_archived == []


def test_rotation_and_archival_never_raises_and_labels_the_gap(tmp_path: Path) -> None:
    """Build-item 4: force a checkpoint -> new segment; unmount one -> readers
    report "archived -- mount to view", never a 500 (an unhandled exception)."""
    from cll.checkpoint.emit import (
        Signer as _SignerProtocol,  # noqa: F401 -- documents the shape below
    )
    from cll.ledger.segments import MmrCheckpointer

    ledger_dir = tmp_path / "rotating"
    store = open_ledger_store(ledger_dir, log_id="rotation-demo")
    store._max_segment_bytes = 200  # force rotation almost immediately, deterministically

    class _FixedSigner:
        key_id = "00" * 32

        def sign(self, digest_hex: str) -> str:
            return "00" * 64

    mmr = MmrLedger(store)
    store.set_checkpointer(MmrCheckpointer(mmr=mmr, signer=_FixedSigner(), log_id="rotation-demo"))

    capsules = [{"capsule_id": f"{i:064x}", "n": i, "payload": "x" * 40} for i in range(30)]
    for cap in capsules:
        store.append(cap)

    segments = store.list_segments()
    assert len(segments) >= 2, "expected at least one rotation to have fired"
    closed = [s for s in segments if s.manifest is not None]
    assert closed, "expected at least one closed segment with a manifest"

    to_unmount = closed[0]
    store.unmount_segment(to_unmount.name)
    store.close()

    # A fresh read (new process posture: reopen from disk) must never raise --
    # it reports the gap, labeled, and still returns every record it can.
    records, archived = read_all_capsules(ledger_dir)
    assert any(a["segment"] == to_unmount.name for a in archived)
    unmounted_entry = next(a for a in archived if a["segment"] == to_unmount.name)
    assert unmounted_entry["kind"] == ARCHIVED_SEGMENT_KIND
    assert unmounted_entry["note"] == "archived -- mount to view"
    assert unmounted_entry["record_count"] > 0

    # Records outside the unmounted segment are still readable.
    total_visible = len(records) + sum(a["record_count"] for a in archived)
    assert total_visible == len(capsules)

    # Mounting it back makes everything visible again, byte-identical.
    store2 = open_ledger_store(ledger_dir, log_id="rotation-demo")
    store2.mount_segment(to_unmount.name)
    store2.close()
    records_after_mount, archived_after_mount = read_all_capsules(ledger_dir)
    assert archived_after_mount == []
    assert records_after_mount == capsules
