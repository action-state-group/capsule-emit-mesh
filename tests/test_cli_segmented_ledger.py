# SPDX-License-Identifier: Apache-2.0
"""[mesh-live-tab-pane-proxy] L0 -- the CLI ledger_dir/read bug this task's
Q3 ruling folds in: `capsule_accountability_tab.py`'s and
`capsule_exchange_tab.py`'s `_cmd_html`/`_cmd_list` used to read
`--ledger .../capsules.jsonl` as a flat file via `capsule_emit.ledger.
read_ledger(path)` -- which raises `FileNotFoundError` once a ledger dir is
migrated to a segmented `LedgerStore` (the flat file is renamed to
`capsules.jsonl.pre-store-migration`; the real records move to
`segments/seg-NNNNNN.jsonl`). Real (though non-mesh-shaped) fixture
ledgers, migrated in-test, prove both CLIs now find every record post-
migration via `ledger_store_backend.read_all_capsules`/`as_ledger_dir`.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import capsule_accountability_tab
import capsule_exchange_tab
import pytest
from ledger_store_backend import import_flat_ledger_once, open_ledger_store

REPO_ROOT = Path(__file__).parent.parent
REAL_DEMO_LEDGERS = ["ledger-checkpoint-demo", "ledger-real-deployment"]


def _migrated_ledger_dir(demo_name: str, tmp_path: Path) -> Path:
    ledger_dir = tmp_path / demo_name
    shutil.copytree(REPO_ROOT / demo_name, ledger_dir)
    store = open_ledger_store(ledger_dir, log_id=f"{demo_name}-cli-test")
    try:
        import_flat_ledger_once(ledger_dir, store)
    finally:
        store.close()
    assert not (ledger_dir / "capsules.jsonl").exists(), "fixture must actually be migrated for this test to mean anything"
    return ledger_dir


@pytest.mark.parametrize("demo_name", REAL_DEMO_LEDGERS)
def test_accountability_tab_cli_finds_records_in_a_segmented_ledger(demo_name: str, tmp_path: Path) -> None:
    ledger_dir = _migrated_ledger_dir(demo_name, tmp_path)
    flat_record_count = len(
        (REPO_ROOT / demo_name / "capsules.jsonl").read_text(encoding="utf-8").strip().splitlines()
    )
    out = tmp_path / "accountability.html"

    # The conventional --ledger argument still names the (now-nonexistent)
    # flat file path -- as_ledger_dir must resolve it to the ledger dir.
    rc = capsule_accountability_tab.main(["--ledger", str(ledger_dir / "capsules.jsonl"), "--out", str(out)])

    assert rc == 0
    assert out.exists() and out.stat().st_size > 0
    html = out.read_text(encoding="utf-8")
    assert f"{flat_record_count} exchange" in html or str(flat_record_count) in html


@pytest.mark.parametrize("demo_name", REAL_DEMO_LEDGERS)
def test_exchange_tab_cli_list_finds_records_in_a_segmented_ledger(demo_name: str, tmp_path: Path, capsys) -> None:
    ledger_dir = _migrated_ledger_dir(demo_name, tmp_path)
    flat_record_count = len(
        (REPO_ROOT / demo_name / "capsules.jsonl").read_text(encoding="utf-8").strip().splitlines()
    )
    out = tmp_path / "exchanges.html"

    rc = capsule_exchange_tab.main(["list", "--ledger", str(ledger_dir / "capsules.jsonl"), "--out", str(out)])

    assert rc == 0
    assert out.exists() and out.stat().st_size > 0
    # The regression this guards: the pre-fix CLI didn't crash on a
    # migrated (segmented) ledger, it silently reported "0 exchange(s)" --
    # rc == 0 and a non-empty HTML shell alone would not have caught that.
    printed = capsys.readouterr().out
    assert "0 exchange(s)" not in printed
    assert f"{flat_record_count} exchange(s)" in printed


@pytest.mark.parametrize("demo_name", REAL_DEMO_LEDGERS)
def test_exchange_tab_cli_single_finds_a_record_in_a_segmented_ledger(demo_name: str, tmp_path: Path) -> None:
    ledger_dir = _migrated_ledger_dir(demo_name, tmp_path)
    first_line = (REPO_ROOT / demo_name / "capsules.jsonl").read_text(encoding="utf-8").splitlines()[0]
    import json

    capsule_id = json.loads(first_line)["capsule_id"]
    out = tmp_path / "single.html"

    rc = capsule_exchange_tab.main(
        ["single", "--ledger", str(ledger_dir / "capsules.jsonl"), "--capsule-id", capsule_id, "--out", str(out)]
    )

    assert rc == 0
    assert out.exists() and out.stat().st_size > 0
