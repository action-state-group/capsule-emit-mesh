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
def test_each_stated_verdict_is_a_recorded_grade(part):
    assert part.verdict in runbook.recorded_grades(part.doc, part.row)


def test_uncaught_is_not_read_as_caught():
    # RUNG1 row 4's Outcome reads "residual (uncaught)".
    assert runbook.recorded_grades("docs/REDTEAM-RUNG1.md", "4") == ["residual"]


def test_a_split_row_yields_every_branch():
    assert runbook.recorded_grades("docs/REDTEAM-RUNG1.md", "4b") == ["caught", "residual"]


def test_missing_row_has_no_grade():
    assert runbook.recorded_grades("docs/REDTEAM-RUNG1.md", "999") == []


_REAL_RUN_CARGO = runbook.run_cargo


def _all_pass(monkeypatch):
    monkeypatch.setattr(runbook, "run_pytest", lambda ids: ({i.split("::")[-1]: True for i in ids}, ""))
    monkeypatch.setattr(runbook, "run_cargo", lambda target, name: (True, ""))


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
    monkeypatch.setattr(runbook, "run_cargo", lambda target, name: (False, "boom-cause"))
    assert runbook.main([]) == 1
    out = capsys.readouterr().out
    assert "FAILED" in out
    assert "boom-cause" in out  # the presenter sees why


def test_a_test_that_did_not_run_is_a_mismatch(monkeypatch, capsys):
    _all_pass(monkeypatch)
    monkeypatch.setattr(runbook, "run_pytest", lambda ids: ({}, ""))
    assert runbook.main([]) == 1
    assert "NOT RUN" in capsys.readouterr().out


def test_no_cargo_marks_rust_parts_not_run(monkeypatch, capsys):
    _all_pass(monkeypatch)
    assert runbook.main(["--no-cargo"]) == 1
    assert "NOT RUN" in capsys.readouterr().out


def test_dropping_a_branch_of_a_split_row_is_a_mismatch(monkeypatch, capsys):
    _all_pass(monkeypatch)
    attack = runbook.ATTACKS[1]
    monkeypatch.setattr(attack, "parts", [p for p in attack.parts if not (p.row == "4b" and p.verdict == "residual")])
    assert runbook.main([]) == 1
    assert "MISMATCH" in capsys.readouterr().out


def test_missing_cargo_prints_not_run_and_the_closing_line(monkeypatch, capsys):
    _all_pass(monkeypatch)
    monkeypatch.setenv("PATH", "/nonexistent")
    monkeypatch.setattr(runbook, "run_cargo", _REAL_RUN_CARGO)
    assert runbook.main([]) == 1
    out = capsys.readouterr().out
    assert "cargo could not start" in out
    assert out.rstrip().endswith("MISMATCH: see the lines above")



def test_run_pytest_reads_pass_fail_and_skip(tmp_path):
    sample = tmp_path / "test_sample.py"
    sample.write_text(
        "import pytest\n"
        "def test_ok():\n    assert True\n"
        "def test_bad():\n    assert False\n"
        "@pytest.mark.skip(reason='x')\ndef test_skipped():\n    pass\n"
    )
    results, output = runbook.run_pytest([f"{sample}::test_ok", f"{sample}::test_bad", f"{sample}::test_skipped"])
    assert results == {"test_ok": True, "test_bad": False, "test_skipped": None}
    assert "pytest exit 1" in output


@pytest.mark.parametrize(
    ("stdout", "expected"),
    [
        ("running 1 test\ntest x ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored", True),
        ("running 1 test\ntest x ... FAILED\n\ntest result: FAILED. 0 passed; 1 failed; 0 ignored", False),
        ("running 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored", None),
        ("error[E0425]: cannot find value", None),
    ],
)
def test_parse_cargo_summary(stdout, expected):
    assert runbook.parse_cargo_summary(stdout) is expected


def test_run_pytest_keeps_exit_code_and_python_above_a_long_tail(tmp_path):
    sample = tmp_path / "test_noisy.py"
    sample.write_text("def test_noisy():\n" + "".join(f"    print({i})\n" for i in range(40)) + "    assert False\n")
    _, output = runbook.run_pytest([f"{sample}::test_noisy", "-s"])
    assert output.splitlines()[0].startswith("(pytest exit 1, python ")


def test_slide_note_prints_after_the_graded_parts(monkeypatch, capsys):
    _all_pass(monkeypatch)
    assert runbook.main([]) == 0
    out = capsys.readouterr().out
    block = out[out.index("[2] "):out.index("[3] ")]
    assert "slide   : Shown from the prototype harness, not a live node" in block
    assert "You hold N halves; it shows about N/2." in block
    assert block.index("slide   :") > block.rindex("-> MATCH")
