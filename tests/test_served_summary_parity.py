# SPDX-License-Identifier: Apache-2.0
"""T8 (invariance) for ``served_summary/1`` against the Mesh-LLM capsules
plugin (``crates/evidence-plugin/src/served_summary.rs``), which names this
module as the check on its served summary.

``tests/fixtures/evidence-interop/served-summary-t8/`` holds the plugin's
parity corpus ledger with one adjudication appended after the newest
checkpoint, that corpus's checkpoints, and the served summary the plugin
answered over it (identical for two requesters). See that directory's
README for how it was made.
"""
from __future__ import annotations

import json
from pathlib import Path

from served_summary import answer_served_summary_request

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "evidence-interop" / "served-summary-t8"


def _jsonl(name: str) -> list[dict]:
    return [json.loads(line) for line in (FIXTURES / name).read_text().splitlines() if line]


def _answer_bytes(capsule_records: list[dict], checkpoint_lines: list[dict]) -> bytes:
    answer = answer_served_summary_request(
        capsule_records=capsule_records,
        checkpoint_lines=checkpoint_lines,
        expected_pin=checkpoint_lines[-1]["root"],
    )
    assert answer["status"] == "ok"
    return json.dumps(answer["served_summary"], sort_keys=True, separators=(",", ":")).encode("utf-8")


def test_the_reference_answers_the_plugins_bytes_for_the_t8_fixture():
    plugin = (FIXTURES / "served_summary.json").read_bytes()
    assert _answer_bytes(_jsonl("capsules.jsonl"), _jsonl("checkpoints.jsonl")) == plugin


def test_the_verdict_after_the_checkpoint_does_not_change_the_bytes():
    capsules = _jsonl("capsules.jsonl")
    checkpoints = _jsonl("checkpoints.jsonl")
    assert "adjudication" in capsules[-1]["model_attestation"]["compute_attestation"]
    assert _answer_bytes(capsules[:-1], checkpoints) == _answer_bytes(capsules, checkpoints)
