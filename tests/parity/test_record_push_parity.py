# SPDX-License-Identifier: Apache-2.0
"""The record-push parity harness checks itself.

1. The Python door, run over the corpus now, gives exactly the golden
   answers (so the golden file is what the door answers, not a stale copy).
2. The comparison catches a single changed answer in any case: every case is
   mutated in turn, and each mutation must be reported against that case and
   no other.
3. The corpus reaches every refusal reason the record-push path can give.
4. Each intended difference names a real case, says why, and really differs
   from the golden answer.
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import compare  # noqa: E402
import record_push_python  # noqa: E402

CORPUS = json.loads(compare.CORPUS.read_text(encoding="utf-8"))
GOLDEN = json.loads(compare.GOLDEN.read_text(encoding="utf-8"))
INTENDED = json.loads(compare.INTENDED.read_text(encoding="utf-8"))["cases"]
NAMES = [c["name"] for c in CORPUS["cases"]]

#: Every reason record_push.py refuses a pushed record or bundle with. A
#: delivered referee verdict (adjudication_hold) is not the record-push path
#: and is not in this corpus; see README.md.
RECORD_PUSH_REASONS = {
    "request_malformed",
    "bundle_malformed",
    "policy_decline",
    "signature_unverified",
    "served_by_mismatch",
    "model_mismatch",
    "inclusion_unverified",
    "checkpoint_stale",
    "checkpoint_equivocation",
}


@pytest.fixture(scope="module")
def python_answers() -> dict:
    return record_push_python.run(CORPUS)


def test_the_python_door_gives_exactly_the_golden_answers(python_answers):
    assert python_answers["path"] == GOLDEN["path"] == CORPUS["path"]
    diffs = compare.compare(python_answers["answers"], GOLDEN["answers"])
    assert diffs == [], "\n".join(f"{n}[{i}]: expected {w}\n got {g}" for n, i, w, g in diffs[:5])


def _mutations(answers: list) -> list:
    """Single changes to one case's answers, each of a different kind."""
    out = []
    first = answers[0]
    reply = first["reply"]
    m = copy.deepcopy(answers)
    if "refused" in reply:
        m[0]["reply"]["refused"] = "policy_decline" if reply["refused"] != "policy_decline" else "request_malformed"
    else:
        m[0]["reply"]["status"] = "refused"
    out.append(m)
    m = copy.deepcopy(answers)
    m[0]["appended"]["unexpected-file.jsonl"] = [{}]
    out.append(m)
    m = copy.deepcopy(answers)
    m.append(copy.deepcopy(first))
    out.append(m)
    if "refused" in reply:
        m = copy.deepcopy(answers)
        m[0]["reply"]["signed_by_node"] = not reply["signed_by_node"]
        out.append(m)
    for name, entries in first["appended"].items():
        m = copy.deepcopy(answers)
        del m[0]["appended"][name][-1]
        out.append(m)
    return out


@pytest.mark.parametrize("name", NAMES)
def test_a_single_changed_answer_is_reported_against_its_case(name):
    for mutated in _mutations(GOLDEN["answers"][name]):
        answers = {**GOLDEN["answers"], name: mutated}
        diffs = compare.compare(answers, GOLDEN["answers"])
        assert {d[0] for d in diffs} == {name}


def test_a_missing_or_extra_case_is_reported():
    answers = dict(GOLDEN["answers"])
    removed = answers.pop(NAMES[0])
    assert {d[0] for d in compare.compare(answers, GOLDEN["answers"])} == {NAMES[0]}
    answers[NAMES[0]] = removed
    answers["not-a-case"] = removed
    assert {d[0] for d in compare.compare(answers, GOLDEN["answers"])} == {"not-a-case"}


def test_the_command_line_fails_on_one_changed_answer(tmp_path, capsys):
    good = tmp_path / "good.json"
    good.write_text(json.dumps(GOLDEN), encoding="utf-8")
    assert compare.main([str(good), "--golden-only"]) == 0
    bad = copy.deepcopy(GOLDEN)
    bad["answers"][NAMES[-1]][0]["reply"]["status"] = "changed"
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(bad), encoding="utf-8")
    assert compare.main([str(path), "--golden-only"]) == 1
    assert f"DIFFERS {NAMES[-1]}[push 0]" in capsys.readouterr().err


def test_the_corpus_reaches_every_record_push_refusal_and_both_success_replies():
    seen = set()
    inclusion = bare = False
    for answers in GOLDEN["answers"].values():
        for answer in answers:
            reply = answer["reply"]
            if "refused" in reply:
                seen.add(reply["refused"])
                assert answer["appended"].keys() <= {
                    "rejected-record-pushes.jsonl",
                    "checkpoint-equivocations.jsonl",
                }, "a refusal never holds anything"
            elif "inclusion" in reply:
                inclusion = True
            else:
                bare = True
    assert seen == RECORD_PUSH_REASONS
    assert inclusion and bare


def test_every_refusal_is_signed_by_the_node_over_the_body_at_the_clock():
    for name, answers in GOLDEN["answers"].items():
        for answer in answers:
            reply = answer["reply"]
            if "refused" in reply:
                assert reply["signed_by_node"], name
                assert reply["request_digest_is_body_sha256"], name
                assert reply["issued_at_is_now"], name


@pytest.mark.parametrize("name", sorted(INTENDED))
def test_each_intended_difference_is_explained_and_real(name):
    entry = INTENDED[name]
    assert name in NAMES
    assert len(entry["why"]) > 40
    assert compare.canonical(entry["answers"]) != compare.canonical(GOLDEN["answers"][name])
