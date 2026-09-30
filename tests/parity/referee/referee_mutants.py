# SPDX-License-Identifier: Apache-2.0
"""The implementation mutants the referee corpus must catch.

A mutant is one deliberate fault in an implementation. The Rust port builds
each behind the cargo feature named here and its parity run must then fail,
on the cases listed in ``mutants.json`` (``must_fail``).

The lists are not guesses. Each fault is made here, in the Python that gives
the expected answers (the reference for a Python-judged path, the rule model
for a rule-stated one), the corpus is run, and the cases whose answers change
are the list. ``test_referee_parity.py`` re-runs this and requires
``mutants.json`` to say the same.
"""
from __future__ import annotations

import json
from contextlib import contextmanager

import referee_common as common
import referee_compare
import referee_rule_model as model

#: A fault made in the rule model (``referee_rule_model.py``).
RULE = "rule"
#: A fault made by patching the Python reference.
REFERENCE = "reference"

MUTANTS = [
    {
        "name": model.MUTANT_SKIPS_BAR_WINDOW,
        "feature": "mutant-referee-select-skips-bar-window",
        "kind": RULE,
        "paths": ["select"],
        "port_module": "referee/bar.rs, referee/select.rs",
        "fault": "A node with a contradiction for the model inside the bar window is treated as eligible.",
    },
    {
        "name": model.MUTANT_MIXES_TIERS,
        "feature": "mutant-referee-select-mixes-tiers",
        "kind": RULE,
        "paths": ["select"],
        "port_module": "referee/select.rs",
        "fault": "The pick is made over every eligible node, not inside the best non-empty tier.",
    },
    {
        "name": model.MUTANT_ASKS_TWICE,
        "feature": "mutant-referee-request-asks-twice-per-pair",
        "kind": RULE,
        "paths": ["request"],
        "port_module": "referee/request.rs",
        "fault": "The one-call cap is not checked: a pair already asked about is asked about again.",
    },
    {
        "name": model.MUTANT_SKIPS_ASKED_GATE,
        "feature": "mutant-referee-counts-skip-asked-gate",
        "kind": RULE,
        "paths": ["counts"],
        "port_module": "referee/verdict_counts.rs",
        "fault": "A received verdict counts whether or not this node asked that referee about that pair.",
    },
    {
        "name": "verdict-names-wrong-twin",
        "feature": "mutant-referee-verdict-names-wrong-twin",
        "kind": REFERENCE,
        "paths": ["adjudicate", "service"],
        "port_module": "referee/verdict.rs",
        "fault": "The ruling names the twin the referee agreed with as the contradicted one.",
    },
    {
        "name": "hold-skips-asked-check",
        "feature": "mutant-referee-hold-skips-asked-check",
        "kind": REFERENCE,
        "paths": ["hold"],
        "port_module": "referee/hold.rs",
        "fault": "Every delivered verdict is treated as one this node asked for.",
    },
]


@contextmanager
def _reference_fault(name: str):
    """The Python reference with the named fault, for the duration."""
    import adjudication_hold
    import live_referee
    import referee_service

    saved = (live_referee.referee_verdict, referee_service.referee_verdict, adjudication_hold._asked)
    if name == "verdict-names-wrong-twin":
        genuine = live_referee.referee_verdict

        def wrong_twin(half_a, half_b, comparison, referee_text):
            verdict = genuine(half_a, half_b, comparison, referee_text)
            prefix = "contradicted:"
            if not verdict.startswith(prefix):
                return verdict
            named = verdict[len(prefix):]
            return prefix + (half_b.owner_id if named == half_a.owner_id else half_a.owner_id)

        live_referee.referee_verdict = referee_service.referee_verdict = wrong_twin
    elif name == "hold-skips-asked-check":
        adjudication_hold._asked = lambda ledger_dir, referee, halves: True
    else:
        raise ValueError(f"unknown reference mutant {name!r}")
    try:
        yield
    finally:
        live_referee.referee_verdict, referee_service.referee_verdict, adjudication_hold._asked = saved


def answers_with(mutant: dict, path: str) -> dict:
    """``path``'s answers from an implementation with ``mutant``'s fault."""
    if mutant["kind"] == RULE:
        return {case["name"]: model.MODELS[path](case, mutant["name"]) for case in common.corpus(path)["cases"]}
    import referee_python

    with _reference_fault(mutant["name"]):
        return referee_python.run(path)["answers"]


def failing_cases(mutant: dict) -> list[str]:
    """Every case (``path/name``) whose answer the fault changes."""
    out = []
    for path in mutant["paths"]:
        expected = common.read(common.expected_file(path))["answers"]
        out += sorted({f"{path}/{d[0]}" for d in referee_compare.compare(answers_with(mutant, path), expected)})
    return out


def document() -> dict:
    return {
        "v": 1,
        "note": (
            "Implementation mutants for the Rust runner. Build the port with 'feature' and run its referee parity "
            "test: the run must fail, and every case in 'must_fail' must be among the cases it reports. "
            "The lists are produced by referee_mutants.py, which makes each fault in the Python that gives the "
            "expected answers and records the cases whose answers change."
        ),
        "mutants": [
            {**{k: v for k, v in mutant.items() if k != "kind"}, "must_fail": failing_cases(mutant)}
            for mutant in MUTANTS
        ],
    }


def write() -> None:
    common.MUTANTS.write_text(json.dumps(document(), indent=1, sort_keys=True) + "\n", encoding="utf-8")
