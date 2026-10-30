# SPDX-License-Identifier: Apache-2.0
"""scripts/redteam_four_attacks.py: verdicts are checked against the recorded
grade, and every miss (wrong verdict, failed or missing test) exits 1."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "redteam_four_attacks", Path(__file__).resolve().parent.parent / "scripts" / "redteam_four_attacks.py"
)
runbook = importlib.util.module_from_spec(_SPEC)
# dataclasses resolves field types through sys.modules.
sys.modules[_SPEC.name] = runbook
_SPEC.loader.exec_module(runbook)


def _parts():
    return [part for attack in runbook.ATTACKS for part in attack.parts]


@pytest.mark.parametrize("part", _parts(), ids=lambda p: f"{Path(p.doc).stem}-row{p.row}")
def test_each_stated_verdict_matches_the_recorded_grade(part):
    assert runbook.recorded_grade(part.doc, part.row) == part.verdict


def test_uncaught_is_not_read_as_caught():
    # RUNG1 row 4's Outcome reads "residual (uncaught)".
    assert runbook.recorded_grade("docs/REDTEAM-RUNG1.md", "4") == "residual"


def test_missing_row_has_no_grade():
    assert runbook.recorded_grade("docs/REDTEAM-RUNG1.md", "999") is None


def _all_pass(monkeypatch):
    monkeypatch.setattr(runbook, "run_pytest", lambda ids: {i.split("::")[-1]: True for i in ids})
    monkeypatch.setattr(runbook, "run_cargo", lambda target, name: True)


def test_all_passing_harnesses_exit_zero(monkeypatch, capsys):
    _all_pass(monkeypatch)
    assert runbook.main([]) == 0
    assert "ALL MATCH" in capsys.readouterr().out


def test_a_wrong_verdict_is_a_mismatch(monkeypatch, capsys):
    _all_pass(monkeypatch)
    monkeypatch.setattr(runbook.ATTACKS[1].parts[0], "verdict", "caught")
    assert runbook.main([]) == 1
    assert "MISMATCH" in capsys.readouterr().out


def test_a_failed_test_is_a_mismatch(monkeypatch, capsys):
    _all_pass(monkeypatch)
    monkeypatch.setattr(runbook, "run_cargo", lambda target, name: False)
    assert runbook.main([]) == 1
    assert "FAILED" in capsys.readouterr().out


def test_a_test_that_did_not_run_is_a_mismatch(monkeypatch, capsys):
    _all_pass(monkeypatch)
    monkeypatch.setattr(runbook, "run_pytest", lambda ids: {})
    assert runbook.main([]) == 1
    assert "NOT RUN" in capsys.readouterr().out


def test_no_cargo_marks_rust_parts_not_run(monkeypatch, capsys):
    _all_pass(monkeypatch)
    assert runbook.main(["--no-cargo"]) == 1
    assert "NOT RUN" in capsys.readouterr().out
