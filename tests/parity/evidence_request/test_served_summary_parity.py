# SPDX-License-Identifier: Apache-2.0
"""The served summary in the evidence-request golden answers is the Python
fold's value (``served_summary.build_served_summary``), exactly.

The rest of the evidence-request answers are judged by the draft, not by the
Python door (see README.md). The served summary is plugin glue the draft does
not define, so the Python fold still judges it: rebuilt here from the
corpus's own ledger and newest checkpoint, it must equal the value the Rust
responder served, member for member."""
from __future__ import annotations

import json
from pathlib import Path

from capsule_emit.checkpoint import CheckpointRecord

from history_card import node_id_from_key_id
from served_summary import build_served_summary

HERE = Path(__file__).parent


def _load(name: str) -> dict:
    return json.loads((HERE / name).read_text(encoding="utf-8"))


def test_the_served_summary_is_the_python_fold():
    corpus = _load("corpus.json")
    golden = _load("golden.json")
    latest = corpus["checkpoints"][-1]
    python = build_served_summary(
        node_id=node_id_from_key_id(latest["key_id"]),
        capsule_records=corpus["ledger"],
        latest_checkpoint=CheckpointRecord.from_dict(latest),
        # The plugin writes the ledger, so a record without an explicit role
        # is read as the plugin's (served), as the Rust fold reads it.
        source_log="plugin",
    ).to_value()
    served = [a["reply"]["served_summary"] for a in golden["answers"].values() if "served_summary" in a["reply"]]
    assert served, "no golden answer carries a served summary"
    for value in served:
        assert value == python


def test_the_corpus_folds_something_on_both_sides_of_the_floor():
    golden = _load("golden.json")
    by_model = golden["answers"]["served_summary"]["reply"]["served_summary"]["derivation"]["by_model"]
    assert any(m["floor_applied"] for m in by_model.values())
    assert any(not m["floor_applied"] for m in by_model.values())
