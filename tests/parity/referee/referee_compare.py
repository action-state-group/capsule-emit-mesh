# SPDX-License-Identifier: Apache-2.0
"""Compare an implementation's referee answers with the expected answers.

    python tests/parity/referee/referee_compare.py ANSWERS.json [--golden-only] [--table]

ANSWERS holds one or more paths (``{"paths": {"<path>": {"<case>": [...]}}}``);
only the paths it holds are compared, so a port can be run one path at a time.

The expected answer for a case is the Python reference's (``golden/``) or,
for a path with no Python reference, the rule's (``rule_answers/``), except
for the cases listed in ``intended_differences.json``: there the port is held
to the listed answer instead. Pass ``--golden-only`` when ANSWERS is the
Python reference's own output.

Exit 0 when every case matches, 1 when any answer differs (each difference
is printed), 2 when ANSWERS does not describe this corpus.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import referee_common as common
from referee_common import canonical


def expected_answers(path: str, golden_only: bool = False) -> tuple[dict, set[str]]:
    """``(expected answers by case, the cases held to an intended difference)``."""
    expected = dict(common.read(common.expected_file(path))["answers"])
    intended: set[str] = set()
    if golden_only:
        return expected, intended
    for key, entry in common.read(common.INTENDED)["cases"].items():
        entry_path, _, name = key.partition("/")
        if entry_path != path:
            continue
        if name not in expected:
            raise SystemExit(f"intended_differences.json names unknown case {key!r}")
        expected[name] = entry["answers"]
        intended.add(name)
    return expected, intended


def compare(answers: dict, expected: dict) -> list[tuple[str, int, str, str]]:
    """Every (case, answer index, expected, got) that differs; a missing or
    extra case or answer is a difference too."""
    diffs = []
    for name in sorted(set(expected) | set(answers)):
        want = expected.get(name)
        got = answers.get(name)
        if want is None or got is None:
            diffs.append((name, -1, "present" if want else "absent", "present" if got else "absent"))
            continue
        for i in range(max(len(want), len(got))):
            w = want[i] if i < len(want) else None
            g = got[i] if i < len(got) else None
            if canonical(w) != canonical(g):
                diffs.append((name, i, canonical(w), canonical(g)))
    return diffs


def label(answer) -> str:
    """A short summary of one answer, for the table."""
    if not isinstance(answer, dict):
        return "?"
    if "error" in answer:
        return answer["error"]
    if "reply" in answer:
        reply = answer["reply"]
        return str(reply.get("refused") or reply.get("verdict") or reply.get("status") or "?")
    if "row" in answer:
        row = answer["row"]
        return f"{answer['referee_calls']} call: " + str(row.get("verdict") or row.get("reason"))
    if "pool" in answer:
        return answer["not_adjudicated"] or f"tier {answer['tier']}: {', '.join(answer['asked'])}"
    if "outcomes" in answer:
        return ", ".join(o["outcome"] for o in answer["outcomes"]) or "nothing asked of the host"
    if "no_verdict_reason" in answer:
        return str(answer["verdict"] or answer["no_verdict_reason"])
    if "ack_refusals" in answer:
        return " ".join(f"{k}={v}" for k, v in answer.items() if v) or "nothing counted"
    return "?"


def table(path: str, answers: dict, expected: dict, intended: set[str], implementation: str) -> str:
    rows = [f"| {path} case | expected | {implementation} | match |", "| --- | --- | --- | --- |"]
    for case in common.corpus(path)["cases"]:
        name = case["name"]
        want, got = expected.get(name, []), answers.get(name, [])
        mark = "yes" if canonical(want) == canonical(got) else "**NO**"
        if name in intended:
            mark += " (intended difference)"
        rows.append(f"| {name} | {' · '.join(map(label, want))} | {' · '.join(map(label, got))} | {mark} |")
    return "\n".join(rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("answers", type=Path)
    parser.add_argument("--golden-only", action="store_true", help="hold ANSWERS to the Python reference's answers alone")
    parser.add_argument("--table", action="store_true", help="print the per-case table (markdown)")
    args = parser.parse_args(argv)

    got = common.read(args.answers)
    paths = got.get("paths")
    if not isinstance(paths, dict) or not paths or not set(paths) <= set(common.PATHS):
        print(f"error: ANSWERS must hold 'paths', each one of {', '.join(common.PATHS)}", file=sys.stderr)
        return 2
    implementation = got.get("implementation", "answers")
    failed = False
    for path in common.PATHS:
        if path not in paths:
            continue
        expected, intended = expected_answers(path, args.golden_only)
        diffs = compare(paths[path], expected)
        if args.table:
            print(table(path, paths[path], expected, intended, implementation))
            print()
        for name, i, want, have in diffs:
            where = name if i < 0 else f"{name}[answer {i}]"
            print(f"DIFFERS {path}/{where}\n  expected {want}\n  got      {have}", file=sys.stderr)
        total = len(expected)
        print(f"referee parity, {path}: {total - len({d[0] for d in diffs})}/{total} cases match"
              f" ({len(intended)} intended differences)")
        failed = failed or bool(diffs)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
