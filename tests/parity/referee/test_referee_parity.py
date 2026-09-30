# SPDX-License-Identifier: Apache-2.0
"""The referee parity harness checks itself.

1. The Python reference, run over the corpus now, gives exactly the golden
   answers, except in the listed cases where it departs from the rules (there
   it gives exactly the answers recorded for it), and the rule model gives
   exactly the rule-stated answers.
2. The comparison catches a single changed answer in any case, and reports it
   against that case and no other.
3. The corpus reaches every rule it is meant to hold, every refusal the
   referee paths can give, and every "not adjudicated" reason.
4. Each case where the Python departs names the rule that governs, and the
   golden answer there is the rule's, not the Python's. No golden answer
   carries a match share or a threshold.
5. Each implementation mutant is caught by exactly the cases ``mutants.json``
   lists, and never by none.
6. The corpus is what the builder builds, holds public material only, names
   nodes neutrally, and none of its files grades a node.
"""
from __future__ import annotations

import copy
import json
import re
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import referee_common as common  # noqa: E402
import referee_compare  # noqa: E402
import referee_mutants  # noqa: E402
import referee_python  # noqa: E402
import referee_rule_model as model  # noqa: E402

CORPUS = {path: common.corpus(path) for path in common.PATHS}
EXPECTED = {path: common.read(common.expected_file(path))["answers"] for path in common.PATHS}
INTENDED = common.read(common.INTENDED)
MUTANTS = common.read(common.MUTANTS)
PORT_TESTS = common.read(HERE / "port_tests.json")["tests"]
CASES = [(path, case["name"]) for path in common.PATHS for case in CORPUS[path]["cases"]]
KEYS = {f"{path}/{name}" for path, name in CASES}

#: The rules the corpus must hold (``README.md``), and the paths each is
#: judged in. Every other tag marks supporting cases of a Python-judged path.
RULES = {
    "trigger": {"request"},
    "cap": {"request", "service"},
    "eligibility": {"select", "request"},
    "bar_window": {"select", "counts"},
    "tiers": {"select"},
    "tier_sealed": {"service", "hold"},
    "never_contradicted": {"request"},
    "counts": {"counts", "classify"},
    "stop_rule": {"counts"},
}
SUPPORTING = {"half", "verdict", "delivery", "only_referee_signs"}


@pytest.fixture(scope="module")
def python_answers() -> dict:
    return referee_python.run_all()


# --- 1. the expected answers are what their sources give ----------------------


@pytest.mark.parametrize("path", common.PYTHON_PATHS)
def test_the_python_reference_gives_the_golden_answers_except_where_it_departs(python_answers, path):
    its_own, _ = referee_compare.expected_answers(path, python=True)
    diffs = referee_compare.compare(python_answers[path]["answers"], its_own)
    assert diffs == [], "\n".join(f"{n}[{i}]: expected {w}\n got {g}" for n, i, w, g in diffs[:5])


@pytest.mark.parametrize("path", common.RULE_PATHS)
def test_the_rule_model_gives_exactly_the_rule_stated_answers(path):
    worked_out = {case["name"]: model.MODELS[path](case) for case in CORPUS[path]["cases"]}
    diffs = referee_compare.compare(worked_out, EXPECTED[path])
    assert diffs == [], "\n".join(f"{n}[{i}]: stated {w}\n worked out {g}" for n, i, w, g in diffs[:5])


@pytest.mark.parametrize("path", common.PATHS)
def test_the_answers_and_the_corpus_name_the_same_cases(path):
    assert sorted(EXPECTED[path]) == sorted(case["name"] for case in CORPUS[path]["cases"])
    assert all(isinstance(answers, list) and answers for answers in EXPECTED[path].values())


# --- 2. the comparison ---------------------------------------------------------


@pytest.mark.parametrize("path, name", CASES)
def test_a_single_changed_answer_is_reported_against_its_case(path, name):
    golden = EXPECTED[path][name]
    changed = copy.deepcopy(golden)
    changed[0]["unexpected_member"] = True
    longer = copy.deepcopy(golden) + [copy.deepcopy(golden[0])]
    for mutated in (changed, longer, golden[:-1]):
        diffs = referee_compare.compare({**EXPECTED[path], name: mutated}, EXPECTED[path])
        assert {d[0] for d in diffs} == {name}


def test_a_missing_or_extra_case_is_reported():
    answers = dict(EXPECTED["select"])
    name = next(iter(answers))
    removed = answers.pop(name)
    assert {d[0] for d in referee_compare.compare(answers, EXPECTED["select"])} == {name}
    answers[name] = removed
    answers["not-a-case"] = removed
    assert {d[0] for d in referee_compare.compare(answers, EXPECTED["select"])} == {"not-a-case"}


def _answers_file(tmp_path, name: str, paths: dict) -> Path:
    target = tmp_path / name
    target.write_text(json.dumps({"v": 1, "implementation": "test", "paths": paths}), encoding="utf-8")
    return target


def test_the_command_line_passes_the_expected_answers_and_fails_on_one_change(tmp_path, capsys):
    port = _answers_file(tmp_path, "port.json", EXPECTED)
    assert referee_compare.main([str(port), "--table"]) == 0
    # The Python's own answers pass only as the Python's: it departs from the rules.
    its_own = {path: referee_compare.expected_answers(path, python=True)[0] for path in common.PYTHON_PATHS}
    python = _answers_file(tmp_path, "python.json", its_own)
    assert referee_compare.main([str(python), "--python"]) == 0
    assert referee_compare.main([str(python)]) == 1
    assert referee_compare.main([str(port), "--python"]) == 1
    capsys.readouterr()

    one_path = {"request": copy.deepcopy(EXPECTED["request"])}
    assert referee_compare.main([str(_answers_file(tmp_path, "one.json", one_path))]) == 0
    one_path["request"]["second_call_same_pair_refused"][1]["referee_calls"] = 1
    assert referee_compare.main([str(_answers_file(tmp_path, "bad.json", one_path))]) == 1
    assert "DIFFERS request/second_call_same_pair_refused[answer 1]" in capsys.readouterr().err
    assert referee_compare.main([str(_answers_file(tmp_path, "unknown.json", {"no-such-path": {}}))]) == 2


# --- 3. what the corpus reaches -------------------------------------------------


def _cases_tagged(rule: str) -> dict[str, int]:
    found: dict[str, int] = {}
    for path in common.PATHS:
        count = sum(1 for case in CORPUS[path]["cases"] if case["rule"] == rule)
        if count:
            found[path] = count
    return found


@pytest.mark.parametrize("rule", sorted(RULES))
def test_every_rule_has_cases_in_the_paths_that_judge_it(rule):
    assert RULES[rule] <= set(_cases_tagged(rule)), f"{rule}: {_cases_tagged(rule)}"


def test_every_case_is_tagged_with_a_known_rule_and_says_what_it_covers():
    for path in common.PATHS:
        for case in CORPUS[path]["cases"]:
            assert case["rule"] in set(RULES) | SUPPORTING, (path, case["name"])
            assert len(case["covers"]) >= 10, (path, case["name"])


def test_every_named_port_test_has_a_case():
    named = [key for group in PORT_TESTS.values() for keys in group.values() for key in keys]
    assert all(group.values() for group in PORT_TESTS.values())
    assert set(named) <= KEYS, sorted(set(named) - KEYS)
    assert sum(len(group) for group in PORT_TESTS.values()) >= 44


def _replies(path: str):
    return [answer["reply"] for answers in EXPECTED[path].values() for answer in answers]


def test_the_corpus_reaches_every_ruling_and_every_refusal_of_the_referee():
    import adjudication_hold
    import referee_service
    import twin_adjudicator

    outcomes = [answers[0] for answers in EXPECTED["adjudicate"].values()]
    reasons = {o["no_verdict_reason"] for o in outcomes if "no_verdict_reason" in o} - {None}
    assert reasons == {getattr(twin_adjudicator, n) for n in dir(twin_adjudicator) if n.startswith("NO_VERDICT_")}
    assert {o["error"] for o in outcomes if "error" in o} == {"forged_half", "answer_not_the_signed_body"}
    assert {"corroborated", "inconclusive", "contradicted:node-a", "contradicted:node-b"} <= {
        o.get("verdict") for o in outcomes
    }

    service = _replies("service")
    refused = {r["refused"] for r in service if "refused" in r}
    assert refused == {getattr(referee_service, n) for n in dir(referee_service) if n.startswith("REASON_")}
    assert {r["verdict"] for r in service if "verdict" in r} == {
        "corroborated", "inconclusive", "not_comparable", "contradicted:node-a", "contradicted:node-b",
    }
    because = {r["verdict_capsule"]["block"].get("not_comparable_because") for r in service if "verdict" in r}
    assert because == {None, "sampled", "weights_differ", "weights_unknown"}

    held = {r["refused"] for r in _replies("hold") if "refused" in r}
    door = {getattr(adjudication_hold, n) for n in dir(adjudication_hold) if n.startswith("REASON_")}
    assert held == door | {"request_malformed", "policy_decline", "signature_unverified", "tier_not_as_asked"}
    assert {r["refused"] for r in _replies("deliver") if "refused" in r} == {
        "request_malformed", "policy_decline", "verdict_unverified",
    }


def test_a_refusal_is_signed_by_the_node_and_holds_nothing():
    for path in ("service", "hold", "deliver"):
        for name, answers in EXPECTED[path].items():
            for answer in answers:
                reply = answer["reply"]
                if "refused" not in reply:
                    continue
                assert reply["signed_by_node"] and reply["request_digest_is_body_sha256"], (path, name)
                assert reply["issued_at_is_now"], (path, name)
                if path == "deliver":
                    assert answer["held"] is False, name
                else:
                    assert set(answer["appended"]) <= {"rejected-record-pushes.jsonl"}, (path, name)


def test_every_issued_verdict_is_signed_by_the_referee_and_held_once():
    for name, answers in EXPECTED["service"].items():
        for answer in answers:
            reply = answer["reply"]
            if "verdict" not in reply:
                continue
            assert reply["verdict_capsule"]["signed_by_node"] and reply["verdict_capsule_id_is_the_records"], name
            assert reply["verdict_capsule"]["block"]["verdict"] == reply["verdict"], name
        issued = [line for answer in answers for line in answer["appended"].get("issued-adjudications.jsonl", [])]
        assert len(issued) <= 1, name


def test_not_adjudicated_is_never_a_contradiction():
    """Rule 6: every reason a pair is not adjudicated, and none of them counts
    against either twin or shows a verdict."""
    seen = set()
    for name, answers in EXPECTED["request"].items():
        for answer in answers:
            row = answer["row"]
            if row["state"] == "not_adjudicated":
                seen.add(row["reason"])
                assert answer["counts_against"] is None and "verdict" not in row, name
            else:
                named = row["verdict"].partition("contradicted:")[2] or None
                assert answer["counts_against"] == named, name
    assert seen == {
        "off", "host_does_not_mark_twins", "twins_agree", "not_comparable",
        "no_eligible_referee", "referee_cannot_sign", "referee_unreachable",
    }
    for answers in EXPECTED["select"].values():
        assert (answers[0]["not_adjudicated"] == "no_eligible_referee") == (answers[0]["pool"] == [])


def test_no_pair_is_asked_about_twice():
    """Rule 2: across a case's attempts, each pair gets at most one call."""
    for case in CORPUS["request"]["cases"]:
        calls: dict[tuple, int] = {}
        for attempt, answer in zip(case["attempts"], EXPECTED["request"][case["name"]]):
            pair = attempt["pair"]
            key = (pair["twin_bracket_id"], pair["request_digest"], tuple(sorted(h["node_id"] for h in pair["halves"])))
            calls[key] = calls.get(key, 0) + answer["referee_calls"]
        assert max(calls.values()) <= 1, case["name"]


def test_every_pick_is_inside_the_best_tier_and_every_member_can_be_picked():
    """Rule 4: the draws of the uniform case reach every member of the pool."""
    for case in CORPUS["select"]["cases"]:
        answer = EXPECTED["select"][case["name"]][0]
        assert set(answer["asked"]) <= set(answer["pool"]), case["name"]
        assert answer["pool"] == sorted(answer["pool"])
        assert not set(answer["pool"]) & set(case["twins"])
    uniform = EXPECTED["select"]["pick_uniform_within_best_tier"][0]
    assert len(uniform["pool"]) >= 3 and set(uniform["asked"]) == set(uniform["pool"])


def test_the_provisional_cases_are_the_three_unconfirmed_defaults_and_no_others():
    """Cases whose answer follows a default no ruling has confirmed yet are
    marked, so a later ruling is a small edit; nothing else is marked."""
    marked = {f"{path}/{case['name']}" for path in common.PATHS for case in CORPUS[path]["cases"] if "provisional" in case}
    assert marked == {
        "select/barred_one_second_inside_d",
        "select/eligible_at_exactly_d",
        "select/eligible_one_second_after_d",
        "select/lapsed_contradiction_with_earlier_corroboration_is_tier2",
        "select/lapsed_contradiction_with_older_corroboration_is_tier2",
        "select/lapsed_contradiction_corroborated_after_the_lapse_is_tier1",
        "select/corroborated_one_second_before_the_lapse_is_tier2",
        "select/corroborated_one_second_after_the_lapse_is_tier1",
        "request/no_eligible_referee_is_not_retried_on_its_own",
        "request/no_eligible_referee_then_the_operator_asks_again",
        "request/operator_asks_again_and_still_nobody",
        "request/operator_asking_again_uses_the_one_call",
    }
    # The window is half-open: barred one second inside it, eligible at its end.
    pools = {name: EXPECTED["select"][name][0]["pool"] for name in EXPECTED["select"]}
    assert pools["barred_one_second_inside_d"] == [] and pools["eligible_at_exactly_d"] == ["node-c"]
    # A pair that found nobody eligible is looked at again only when the operator asks.
    for case in CORPUS["request"]["cases"]:
        nobody = False
        for attempt, answer in zip(case["attempts"], EXPECTED["request"][case["name"]]):
            if nobody and not attempt["manual"]:
                assert answer["referee_calls"] == 0, case["name"]
            nobody = answer["row"].get("reason") == "no_eligible_referee"


# --- 4. the intended differences -------------------------------------------------


@pytest.mark.parametrize("key", sorted(INTENDED["cases"]))
def test_each_intended_difference_is_explained_and_real(key):
    entry = INTENDED["cases"][key]
    path, _, name = key.partition("/")
    assert key in KEYS and path in common.PYTHON_PATHS
    assert len(entry["why"]) > 40 and entry["rule"].startswith("rule ")
    assert common.canonical(entry["python_answers"]) != common.canonical(EXPECTED[path][name])


def test_the_golden_answers_and_the_differences_are_what_the_rules_make_of_the_python(python_answers):
    golden, intended = referee_python.derive(python_answers)
    assert intended == INTENDED
    for path in common.PYTHON_PATHS:
        assert golden[path]["answers"] == EXPECTED[path], path


def test_no_golden_answer_encodes_the_pythons_text_threshold():
    """Any difference at temperature 0 on the same weights is a difference:
    no answer reports a match share, and no sealed block carries one."""
    for path in common.PYTHON_PATHS:
        text = common.expected_file(path).read_text(encoding="utf-8")
        assert "margin" not in text, path
    for name, answers in EXPECTED["adjudicate"].items():
        answer = answers[0]
        if answer.get("verdict") == "corroborated":
            assert answer["divergence_index"] is None, name
    assert EXPECTED["adjudicate"]["differ_last_word_no_referee"][0]["verdict"] == "inconclusive"
    assert EXPECTED["adjudicate"]["both_answers_empty"][0]["verdict"] == "corroborated"


def test_twins_without_a_shared_weights_digest_are_never_contradicted():
    for case in CORPUS["adjudicate"]["cases"]:
        digests = [half["weights_digest"] for half in case["halves"]]
        if all(digests) and digests[0] == digests[1]:
            continue
        answer = EXPECTED["adjudicate"][case["name"]][0]
        assert "error" in answer or answer["verdict"] is None, case["name"]
    for name in ("weights_unknown_on_one_side", "weights_unknown_on_both_sides"):
        assert EXPECTED["adjudicate"][name][0]["no_verdict_reason"] == "not_comparable"


def test_each_path_difference_names_its_rule_and_the_python_it_replaces():
    assert set(INTENDED["paths"]) == set(common.RULE_PATHS) | {"adjudicate"}
    for path, entry in INTENDED["paths"].items():
        assert len(entry["why"]) > 40 and entry["rule"], path
    # The Python selection really does depart: it asks nodes the rules bar.
    shown = INTENDED["paths"]["select"]["shown_by"]
    assert {"blocked_node_never_picked", "no_announced_key_never_picked", "barred_inside_d", "tier1_before_tier2"} <= set(shown)


def test_the_sealed_tier_is_the_one_the_requester_stated():
    """Rule 5: tier 1 and tier 2 are both sealed, as asked."""
    tiers = set()
    for name, answers in EXPECTED["service"].items():
        for answer in answers:
            if "verdict" not in answer["reply"]:
                continue
            block = answer["reply"]["verdict_capsule"]["block"]
            assert block["model_hash"] and block["selection_tier"] in (1, 2), name
            tiers.add(block["selection_tier"])
    assert tiers == {1, 2}
    # A request that states no tier, or one outside 1 and 2, gets no verdict.
    for name in ("selection_tier_missing", "selection_tier_out_of_range"):
        assert {a["reply"]["refused"] for a in EXPECTED["service"][name]} == {"request_malformed"}, name


# --- 5. the implementation mutants -----------------------------------------------


def test_the_mutants_file_is_what_the_faults_give():
    assert referee_mutants.document() == MUTANTS


@pytest.mark.parametrize("mutant", MUTANTS["mutants"], ids=lambda m: m["name"])
def test_each_mutant_is_caught_by_cases_of_its_own_path(mutant):
    assert mutant["must_fail"], "a mutant no case catches is not held by this corpus"
    assert set(mutant["must_fail"]) <= KEYS
    assert {key.partition("/")[0] for key in mutant["must_fail"]} == set(mutant["paths"])
    assert mutant["feature"].startswith("mutant-referee-") and len(mutant["fault"]) > 20


def test_the_rules_each_have_a_mutant():
    by_name = {m["name"]: m["must_fail"] for m in MUTANTS["mutants"]}
    assert "select/barred_inside_d" in by_name["select-skips-bar-window"]
    assert "request/second_call_same_pair_refused" in by_name["request-asks-twice-per-pair"]
    # An eligibility check other than the bar, and the sealed tier on both sides.
    assert "select/blocked_node_never_picked" in by_name["select-ignores-blocked"]
    assert "service/tier_two_referee" in by_name["verdict-tier-not-sealed"]
    assert by_name["hold-ignores-the-asked-tier"] == ["hold/hold_refuses_tier_other_than_asked"]


# --- 6. the corpus itself ---------------------------------------------------------


def _files() -> list[Path]:
    return sorted(p for p in HERE.rglob("*") if p.is_file() and "__pycache__" not in p.parts)


def test_the_corpus_is_what_the_builder_builds():
    import build_referee_corpus

    corpus, rule_answers = build_referee_corpus.build()
    assert build_referee_corpus.build() == (corpus, rule_answers), "two builds must agree"
    for path in common.RULE_PATHS:
        assert corpus[path] == CORPUS[path], path
        assert rule_answers[path]["answers"] == EXPECTED[path], path
    for path in common.PYTHON_PATHS:
        if CORPUS[path]["built_with"] != common.library_versions():
            # A different library release may seal a different record; the
            # committed corpus stays the one the golden answers were made from.
            continue
        assert corpus[path] == CORPUS[path], path


def _strings(value, key=None):
    if isinstance(value, dict):
        for k, v in value.items():
            yield from _strings(v, k)
    elif isinstance(value, list):
        for v in value:
            yield from _strings(v, key)
    elif isinstance(value, str):
        yield key, value


def test_nodes_are_named_neutrally():
    node_keys = {
        "id", "node_id", "sender", "referee", "referee_node_id", "referee_id", "peer_id", "x", "asked",
        "served_by_node_id", "half_a_node_id", "half_b_node_id", "owner_id", "claimed_sender_peer_id",
        "received_from", "counts_against", "half_node_ids", "twins", "pool",
    }
    seen = set()
    for path in common.PATHS:
        for key, value in _strings(CORPUS[path]["cases"]):
            if key in node_keys:
                seen.add(value)
    assert seen and all(re.fullmatch(r"node-[a-z]", node) for node in seen), sorted(seen)


def test_the_files_hold_no_key_material():
    for path in _files():
        if path.suffix not in (".json", ".md"):
            continue
        text = path.read_text(encoding="utf-8")
        assert "PRIVATE KEY" not in text and common.KEY_SEED_PREFIX not in text, path.name


def test_no_file_grades_a_node():
    """Eligibility is yes or no. No file here uses the vocabulary of grading
    a node; the words are built from parts so this test does not hold them."""
    words = ["sco" + "re", "sco" + "res", "sco" + "red", "sco" + "ring", "reput" + "ation", "rat" + "ing",
             "rat" + "ings", "rank" + "ing", "rank" + "ed"]
    pattern = re.compile(r"\b(" + "|".join(words) + r")\b", re.IGNORECASE)
    for path in _files():
        found = pattern.findall(path.read_text(encoding="utf-8"))
        assert not found, f"{path.name}: {sorted(set(found))}"
