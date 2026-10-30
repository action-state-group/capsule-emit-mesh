#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run four red-team attacks from the REDTEAM docs and print each verdict.

One command, presenter-ready:

    python3 scripts/redteam_four_attacks.py

For each attack this runs the harness tests the REDTEAM doc cites, then
prints the verdict this runbook states, the grade the doc records for that
row, and MATCH or MISMATCH. Run it with the Python that has this repo's
requirements and pytest installed (the project venv); the harnesses use the
interpreter that launched this script. The recorded grade is read from the doc's
weak-links table at run time, so an edited doc can't silently drift from what
the runbook says. A failing harness test, a test that doesn't exist, or a
verdict that differs from the recorded grade makes the run exit 1.

The harnesses run against this repository's research prototype: the Python
sidecar (rung 1/2) and the Rust `plugins/capsule-producer` crate (rung 3).
They do not run against the Mesh-LLM/capsules plugin on a live mesh.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CARGO_MANIFEST = "plugins/capsule-producer/Cargo.toml"
GRADES = ("caught", "labeled", "residual")


@dataclass
class Part:
    """One graded claim: a stated verdict, the doc row that records it, and
    the harness tests that reproduce it."""

    verdict: str  # one of GRADES
    says: str  # the line the presenter reads out
    doc: str
    row: str
    pytest: list[str] = field(default_factory=list)
    cargo: list[tuple[str, str]] = field(default_factory=list)  # (test target, test fn)


@dataclass
class Attack:
    number: int
    title: str
    parts: list[Part]
    # Printed after the graded parts: the slide's wording for this attack.
    # Not graded here.
    slide_note: list[str] = field(default_factory=list)


RUNG1 = "tests/test_redteam_rung1.py"
RUNG1_REQ = "tests/test_redteam_rung1_requester_half.py"
RUNG2 = "tests/test_redteam_rung2.py"

ATTACKS = [
    Attack(1, "Ledger rewrite", [
        Part("caught", "a rewritten leaf no longer matches the witnessed checkpoint's root",
             "docs/REDTEAM-RUNG1.md", "1",
             pytest=[f"{RUNG1}::test_attack1_equivocation_rewrite_breaks_root",
                     f"{RUNG1}::test_attack1_equivocation_consistency_proof_goes_red"]),
    ]),
    Attack(2, "Selective log (exchanges left out of the node's log)", [
        Part("residual", "the node's log passes every integrity check: rung 1 alone can't see it",
             "docs/REDTEAM-RUNG1.md", "4",
             pytest=[f"{RUNG1}::test_attack4_selective_log_is_perfectly_witness_consistent",
                     f"{RUNG1}::test_attack4_witness_cannot_assert_coverage"]),
        Part("caught", "the requester's own halves name hidden exchanges whose response carried an id, "
             "given the node's records for the range",
             "docs/REDTEAM-RUNG1.md", "4b",
             pytest=[f"{RUNG1_REQ}::test_attack4b_selective_log_is_caught_by_the_requesters_half",
                     f"{RUNG1_REQ}::test_attack4b_an_honest_log_leaves_nothing_missing",
                     f"{RUNG1_REQ}::test_attack4b_without_the_nodes_records_every_half_reads_missing"]),
        Part("residual", "a failure that reached the requester as an id-less error seals 'unknown' "
             "and can't be paired",
             "docs/REDTEAM-RUNG1.md", "4b",
             pytest=[f"{RUNG1_REQ}::test_attack4b_failure_without_a_response_id_stays_residual"]),
    ], slide_note=[
        "Shown from the prototype harness, not a live node: the node drops some exchanges it served.",
        "Its log still passes every integrity check. You hold N halves; it shows about N/2.",
        "Residual in the shipped capsules v0.1.5 plugin (not this harness): a failed exchange "
        "leaves no record on either side, a coverage gap rather than an attack.",
    ]),
    Attack(3, "Model id / quant swap", [
        Part("residual", "a consistent self-reported model claim reconciles clean",
             "docs/REDTEAM-RUNG2.md", "5",
             pytest=[f"{RUNG2}::test_attack5_model_spoof_reconciles_clean_when_lie_is_consistent",
                     f"{RUNG2}::test_attack5_baseline_crosscheck_cannot_see_model_identity"]),
        Part("residual", "a consistent self-reported quant claim reconciles clean",
             "docs/REDTEAM-RUNG2.md", "6",
             pytest=[f"{RUNG2}::test_attack6_quant_swap_reconciles_clean_when_consistent",
                     f"{RUNG2}::test_attack6_baseline_does_not_flag_a_faster_degraded_quant"]),
    ]),
    Attack(4, "Post-signing measurement tamper", [
        Part("caught", "one flipped MRTD byte breaks the hardware quote signature "
             "(test-generated PCK-style chain, not a real Intel quote)",
             "docs/REDTEAM-RUNG3.md", "16",
             cargo=[("redteam_rung3_tee_measured",
                     "attack16_headline_post_signing_measurement_tamper_is_caught_where_self_measured_was_not")]),
    ]),
]


def recorded_grades(doc: str, row: str) -> list[str]:
    """Every caught/labeled/residual word in the Outcome column of the
    weak-links row numbered *row*, in order and without repeats; empty when
    the row or a grade is absent. A split row ("caught when ... / residual
    when ...") yields one grade per branch."""
    for line in (REPO / doc).read_text(encoding="utf-8").splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) >= 4 and cells[0] == row:
            found = re.findall(r"\b(caught|labeled|residual)\b", cells[3].lower())
            return list(dict.fromkeys(found))
    return []


def _tail(text: str, lines: int = 15) -> str:
    return "\n".join(text.strip().splitlines()[-lines:])


def run_pytest(node_ids: list[str]) -> tuple[dict[str, bool | None], str]:
    """Pass (True), fail (False) or skip (None) per test name, plus the tail
    of pytest's output for the presenter when something didn't pass. A test
    pytest didn't run at all is absent from the map."""
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "junit.xml"
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-p", "no:warnings", "-p", "no:cacheprovider",
             f"--junitxml={report}", *node_ids],
            cwd=REPO, stdin=subprocess.DEVNULL, capture_output=True, text=True,
        )
        output = f"(pytest exit {proc.returncode}, python {sys.executable})\n" + _tail(f"{proc.stdout}\n{proc.stderr}")
        if not report.exists():
            return {}, output
        results: dict[str, bool | None] = {}
        for case in ET.parse(report).iter("testcase"):
            tags = {child.tag for child in case}
            results[case.get("name", "")] = None if "skipped" in tags else not tags & {"failure", "error"}
        return results, output


def parse_cargo_summary(stdout: str) -> bool | None:
    """True or False when exactly one test ran, else None."""
    match = re.search(r"test result: \w+\. (\d+) passed; (\d+) failed", stdout)
    if not match or int(match.group(1)) + int(match.group(2)) != 1:
        return None
    return int(match.group(1)) == 1


def run_cargo(target: str, name: str) -> tuple[bool | None, str]:
    """True or False for one exact cargo test, None when it didn't run, plus
    the tail of cargo's output for the presenter."""
    try:
        proc = subprocess.run(
            ["cargo", "test", "--quiet", "--manifest-path", CARGO_MANIFEST, "--test", target, "--", "--exact", name],
            cwd=REPO, stdin=subprocess.DEVNULL, capture_output=True, text=True,
        )
    except OSError as exc:
        return None, f"cargo could not start: {exc}"
    return parse_cargo_summary(proc.stdout), f"(cargo exit {proc.returncode})\n" + _tail(f"{proc.stdout}\n{proc.stderr}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--no-cargo", action="store_true",
                        help="skip the Rust harnesses; their parts print NOT RUN and the run exits 1")
    args = parser.parse_args(argv)

    print("Four attacks, graded caught / labeled / residual.")
    print("Harnesses: capsule-emit-mesh research prototype (Python sidecar, Rust capsule-producer crate),")
    print("not the Mesh-LLM/capsules plugin on a live mesh.\n")

    stated: dict[tuple[str, str], set[str]] = {}
    for attack in ATTACKS:
        for part in attack.parts:
            stated.setdefault((part.doc, part.row), set()).add(part.verdict)

    all_ok = True
    for attack in ATTACKS:
        print(f"[{attack.number}] {attack.title}")
        for part in attack.parts:
            recorded = recorded_grades(part.doc, part.row)
            outcomes: list[tuple[str, bool | None]] = []
            logs: list[str] = []
            if part.pytest:
                results, output = run_pytest(part.pytest)
                outcomes += [(nid, results.get(nid.split("::")[-1])) for nid in part.pytest]
                logs.append(output)
            for target, name in part.cargo:
                if args.no_cargo:
                    ok, output = None, "skipped by --no-cargo"
                else:
                    ok, output = run_cargo(target, name)
                outcomes.append((f"{target}::{name}", ok))
                logs.append(output)

            passed = sum(1 for _, ok in outcomes if ok)
            not_run = [nid for nid, ok in outcomes if ok is None]
            failed = [nid for nid, ok in outcomes if ok is False]
            # A split row needs one part per recorded grade, so no branch of
            # it can be dropped or read out under another branch's verdict.
            verdict_ok = part.verdict in recorded and stated[(part.doc, part.row)] == set(recorded)
            harness_ok = not failed and not not_run
            all_ok = all_ok and verdict_ok and harness_ok

            print(f"    verdict : {part.verdict.upper()}: {part.says}")
            print(f"    recorded: {' / '.join(recorded) or 'NO GRADE FOUND'} ({Path(part.doc).name} row {part.row})")
            print(f"    harness : {passed}/{len(outcomes)} passed"
                  + (f", {len(not_run)} NOT RUN" if not_run else "")
                  + (f", {len(failed)} FAILED" if failed else ""))
            for nid in failed + not_run:
                print(f"              {'FAILED ' if nid in failed else 'NOT RUN'} {nid}")
            if not harness_ok:
                for output in logs:
                    print("              | " + output.replace("\n", "\n              | "))
            print(f"    -> {'MATCH' if verdict_ok and harness_ok else 'MISMATCH'}")
        for line in attack.slide_note:
            print(f"    slide   : {line}")
        print()

    print("ALL MATCH" if all_ok else "MISMATCH: see the lines above")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
