# SPDX-License-Identifier: Apache-2.0
"""Compare an implementation's record-push answers with the golden answers.

    python tests/parity/compare.py ANSWERS.json [--golden-only] [--table]

The expected answer for a case is the golden (Python door) answer, except for
the cases listed in ``intended_differences.json``: there the port is held to
the listed answer instead, and the Python door to the golden one. Pass
``--golden-only`` when ANSWERS is the Python door's own output.

Exit 0 when every case matches, 1 when any answer differs (each difference
is printed), 2 when the files do not describe the same corpus.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORPUS = HERE / "corpus" / "record_push.json"
GOLDEN = HERE / "golden" / "record_push.json"
INTENDED = HERE / "intended_differences.json"


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def label(answer: dict) -> str:
    """A short summary of one push's answer, for the table."""
    reply = answer.get("reply", {})
    head = reply.get("refused") or reply.get("status") or "?"
    return head + ("+inclusion" if "inclusion" in reply else "")


def expected_answers(golden_only: bool) -> tuple[dict, dict]:
    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
    intended = {} if golden_only else json.loads(INTENDED.read_text(encoding="utf-8"))["cases"]
    expected = dict(golden["answers"])
    for name, entry in intended.items():
        if name not in expected:
            raise SystemExit(f"intended_differences.json names unknown case {name!r}")
        expected[name] = entry["answers"]
    return expected, intended


def compare(answers: dict, expected: dict) -> list[tuple[str, int, str, str]]:
    """Every (case, push index, expected, got) that differs; a missing or
    extra case or push is a difference too."""
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


def table(corpus: dict, answers: dict, expected: dict, intended: dict, implementation: str) -> str:
    rows = [f"| case | expected | {implementation} | match |", "| --- | --- | --- | --- |"]
    for case in corpus["cases"]:
        name = case["name"]
        want = expected.get(name, [])
        got = answers.get(name, [])
        ok = canonical(want) == canonical(got)
        mark = "yes" if ok else "**NO**"
        if name in intended:
            mark += " (intended difference)"
        rows.append(
            f"| {name} | {' · '.join(map(label, want))} | {' · '.join(map(label, got))} | {mark} |"
        )
    return "\n".join(rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("answers", type=Path)
    parser.add_argument("--golden-only", action="store_true", help="hold ANSWERS to the golden answers alone")
    parser.add_argument("--table", action="store_true", help="print the per-case table (markdown)")
    args = parser.parse_args(argv)

    corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
    got = json.loads(args.answers.read_text(encoding="utf-8"))
    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
    names = [c["name"] for c in corpus["cases"]]
    if got.get("path") != corpus["path"] or sorted(golden["answers"]) != sorted(names):
        print("error: answers, golden and corpus do not describe the same corpus", file=sys.stderr)
        return 2

    expected, intended = expected_answers(args.golden_only)
    diffs = compare(got["answers"], expected)
    if args.table:
        print(table(corpus, got["answers"], expected, intended, got.get("implementation", "answers")))
        print()
    for name, i, want, have in diffs:
        where = name if i < 0 else f"{name}[push {i}]"
        print(f"DIFFERS {where}\n  expected {want}\n  got      {have}", file=sys.stderr)
    total = len(names)
    print(f"record-push parity: {total - len({d[0] for d in diffs})}/{total} cases match"
          f" ({len(intended)} intended differences)")
    return 1 if diffs else 0


if __name__ == "__main__":
    sys.exit(main())
