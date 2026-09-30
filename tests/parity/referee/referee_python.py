# SPDX-License-Identifier: Apache-2.0
"""Run the referee corpus through the Python reference and write its answers.

    python tests/parity/referee/referee_python.py --out answers.json
    python tests/parity/referee/referee_python.py --golden

``--golden`` rewrites ``golden/*.json`` (the answers the port must give: the
reference's, except where it departs from the rules), then
``intended_differences.json`` (each such departure, with what the Python
answers) and ``mutants.json``.

The answer formats are the harness's contract with every implementation and
are specified in ``README.md``. Each case runs on a fresh node, at the
corpus's fixed clock.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path

import referee_common as common
from referee_common import NOW, Node

from agent_action_capsule.verify import verify as verify_capsule  # noqa: E402
from capsule_emit.evidence_request import Refusal, verify_refusal_offline  # noqa: E402
from capsule_emit.signing import verify_capsule_signature  # noqa: E402

import adjudication_delivery  # noqa: E402
import ask_history  # noqa: E402
import live_referee  # noqa: E402
import referee_service  # noqa: E402
import twin_adjudicator  # noqa: E402
from peer_keys import ENV_PEER_KEYS  # noqa: E402
from record_push import handle_record_push  # noqa: E402

IMPLEMENTATION = "python-reference"
ISSUED = referee_service.ISSUED_ADJUDICATIONS_FILENAME


def body_bytes(entry: dict) -> bytes:
    """A request or delivery body: ``body`` (UTF-8 text) or ``body_b64``."""
    if "body" in entry:
        return entry["body"].encode("utf-8")
    return base64.b64decode(entry["body_b64"])


def normalize_refusal(reply: dict, body: bytes, node_key_id: str) -> dict:
    """A refusal, with its signature checked rather than copied (each
    implementation signs at its own time, and the check is what matters)."""
    try:
        refusal = Refusal(
            request_digest=reply["request_digest"],
            reason=reply["reason"],
            issued_at=reply["issued_at"],
            key_id=reply["key_id"],
            sig=reply["sig"],
        )
        signed = refusal.key_id == node_key_id and verify_refusal_offline(refusal)
    except Exception:  # noqa: BLE001 -- an unreadable refusal is an unsigned one
        signed = False
    return {
        "refused": reply["reason"],
        "status": reply.get("status"),
        "signed_by_node": signed,
        "request_digest_is_body_sha256": reply.get("request_digest") == hashlib.sha256(body).hexdigest(),
        "issued_at_is_now": reply.get("issued_at") == NOW,
    }


# --- adjudicate ---------------------------------------------------------------


def run_adjudicate(case: dict) -> list[dict]:
    halves = []
    for entry in case["halves"]:
        disclosed = {"request_body": entry["request_body"]}
        if entry["response_body"] is not None:
            disclosed["response_body"] = entry["response_body"]
        if "response_text" in entry:
            disclosed["response_text"] = entry["response_text"]
        halves.append(
            twin_adjudicator.AdjudicationHalf(
                capsule=entry["capsule"],
                disclosed=disclosed,
                owner_id=entry["node_id"],
                weights_digest=entry["weights_digest"],
            )
        )
    asked = case["referee"]

    def referee(a, b, comparison):
        if asked.get("unreachable"):
            raise live_referee.RefereeCallError("the referee did not answer")
        return twin_adjudicator.RefereeResult(
            verdict=live_referee.referee_verdict(a, b, comparison, asked["answer_text"]),
            logprobs_absent=True,
            identity=twin_adjudicator.RefereeIdentity(referee_id=asked["node_id"]),
        )

    try:
        outcome = twin_adjudicator.adjudicate(
            *halves,
            referee=referee if asked else None,
            referee_owner_id=asked["node_id"] if asked else None,
        )
    except twin_adjudicator.ForgedHalfError:
        return [{"error": "forged_half"}]
    except twin_adjudicator.PreimageDigestMismatchError:
        return [{"error": "answer_not_the_signed_body"}]
    return [
        {
            "verdict": outcome.verdict,
            "status": twin_adjudicator.status_for_verdict(outcome.verdict) if outcome.verdict else None,
            "no_verdict_reason": outcome.no_verdict_reason,
            "divergence_index": outcome.divergence_index,
            "prefix_digest": outcome.prefix_digest,
            "twin_owner_distinct": outcome.twin_owner_distinct,
            "weights_digest": outcome.weights_digest,
            "referee_called": outcome.referee_called,
        }
    ]


# --- service ------------------------------------------------------------------


class _VerdictNames:
    """Verdict record ids differ between implementations (each seals at its
    own time), so an answer names them ``verdict-1``, ``verdict-2``, ... in
    the order a case first shows them."""

    def __init__(self) -> None:
        self._names: dict[str, str] = {}

    def __call__(self, capsule_id: str) -> str:
        return self._names.setdefault(capsule_id, f"verdict-{len(self._names) + 1}")


def _verdict_summary(capsule: dict, node_key_id: str) -> dict:
    attestation = capsule["model_attestation"]["compute_attestation"]
    return {
        "block": attestation["adjudication"],
        "epistemic_type": attestation.get("epistemic_type"),
        "chain": capsule.get("chain"),
        "provenance": capsule.get("provenance"),
        "signed_by_node": bool(
            verify_capsule(capsule).ok and verify_capsule_signature(capsule) and capsule.get("key_id") == node_key_id
        ),
    }


def _held_summary(held: dict, node_key_id: str, name: _VerdictNames) -> dict:
    out = {k: v for k, v in held.items() if k not in ("verdict_capsule", "verdict_capsule_id", "issued_at")}
    out["verdict_capsule_id"] = name(held["verdict_capsule_id"])
    out["verdict_capsule_id_is_the_records"] = held["verdict_capsule_id"] == held["verdict_capsule"]["capsule_id"]
    out["verdict_capsule"] = _verdict_summary(held["verdict_capsule"], node_key_id)
    out["issued_at_is_now"] = held.get("issued_at") == NOW
    return out


def run_service(case: dict) -> list[dict]:
    name = _VerdictNames()
    answers = []
    saved = referee_service._now_iso
    referee_service._now_iso = lambda: NOW
    try:
        with Node(case["node"]) as node:
            for request in case["requests"]:
                raw = body_bytes(request)
                before = node.line_counts()
                reply = referee_service.handle_adjudicate_request(node.state, raw)
                if "reason" in reply:
                    normal = normalize_refusal(reply, raw, node.key_id)
                    if reply["reason"] == referee_service.REASON_NO_VERDICT:
                        normal["detail"] = reply.get("detail")
                else:
                    normal = _held_summary(reply, node.key_id, name)
                appended = node.appended(before)
                if ISSUED in appended:
                    appended[ISSUED] = [_held_summary(line, node.key_id, name) for line in appended[ISSUED]]
                answers.append({"reply": normal, "appended": appended})
    finally:
        referee_service._now_iso = saved
    return answers


# --- hold ---------------------------------------------------------------------


def run_hold(case: dict) -> list[dict]:
    answers = []
    with Node(case["node"]) as node:
        for push in case["pushes"]:
            raw = body_bytes(push)
            before = node.line_counts()
            reply = handle_record_push(node.state, raw, policy=node.policy, now=NOW, sender_peer_id=push["sender"])
            if "reason" in reply:
                reply = normalize_refusal(reply, raw, node.key_id)
            answers.append({"reply": reply, "appended": node.appended(before)})
    return answers


# --- deliver ------------------------------------------------------------------


def run_deliver(case: dict) -> list[dict]:
    answers = []
    with Node(case["node"]) as node:
        for delivery in case["deliveries"]:
            raw = body_bytes(delivery)
            before = node.line_counts()
            reply = adjudication_delivery.handle_delivery(node.state, raw, now=NOW)
            if "reason" in reply:
                reply = normalize_refusal(reply, raw, node.key_id)
            answers.append({"reply": reply, "held": bool(node.appended(before))})
    return answers


# --- classify -----------------------------------------------------------------


def run_classify(case: dict) -> list[dict]:
    tally = {"corroborated": 0, "contradicted": 0, "inconclusive": 0, "not_comparable": 0, "ack_refusals": 0}
    saved = os.environ.pop(ENV_PEER_KEYS, None)
    os.environ[ENV_PEER_KEYS] = case["peer_keys_env"]
    try:
        ask_history._classify_receipts_for_x(case["receipts"], case["x"], tally)
    finally:
        os.environ.pop(ENV_PEER_KEYS, None)
        if saved is not None:
            os.environ[ENV_PEER_KEYS] = saved
    return [tally]


RUNNERS = {
    "adjudicate": run_adjudicate,
    "service": run_service,
    "hold": run_hold,
    "deliver": run_deliver,
    "classify": run_classify,
}


def run(path: str, corpus: dict | None = None) -> dict:
    corpus = corpus or common.corpus(path)
    return {
        "v": 1,
        "path": path,
        "implementation": IMPLEMENTATION,
        "answers": {case["name"]: RUNNERS[path](case) for case in corpus["cases"]},
    }


def run_all() -> dict:
    return {path: run(path) for path in common.PYTHON_PATHS}


# --- where the port is held to a different answer -----------------------------

#: Whole paths where a Python module exists but is not the reference. The
#: rules are numbered in ``README.md``.
PATH_DIFFERENCES = {
    "select": {
        "python": "twin_selection.select_referee",
        "rule": "rule 3 (eligibility, with the bar window) and rule 4 (tiers)",
        "why": (
            "The Python weighs network distance, owner, hardware and tenure into one number and draws from the "
            "nodes near the top. The rules replace that with yes/no eligibility (the same model hash and weights "
            "digest, not a twin, an announced key, not blocked, no contradiction for that model inside the bar "
            "window) and two tiers (corroborated for that model, then no corroboration yet), with a random pick "
            "inside the best non-empty tier. The bar window is 30 days unless the operator sets it, and a later "
            "corroboration does not end it early. The Python knows none of the announced key, the block list, the "
            "verdict counts or the tiers, so none of its answers is golden: every case's answer is stated from "
            "the rule in rule_answers/select.json. 'shown_by' lists the cases where the Python, given the same "
            "peers, asks a node the rules do not allow."
        ),
    },
    "request": {
        "python": "referee_request.request_verdict",
        "rule": "rule 1 (trigger), rule 2 (one call per pair) and rule 6 (never contradicted)",
        "why": (
            "The Python asks a referee it is handed, every time it is called: no on/off setting, no check that "
            "the host marked the pair as twins, no cap, and it sends an adjudicate request even for twins that "
            "agree. The rules: a referee is asked only when a marked twin pair differs at temperature 0 on the "
            "same weights, at most once per pair and never retried; the operator can turn it off; no eligible "
            "referee, a referee that cannot sign, or one that does not answer is 'not adjudicated' with the "
            "reason, never a contradiction; with no host-supplied twin bracket id nothing is asked and the row "
            "says so. Every case's answer is stated from the rule in rule_answers/request.json."
        ),
    },
    "counts": {
        "python": None,
        "rule": "rule 8 (the counts and the opt-in stop-routing rule)",
        "why": (
            "There is no Python for the counts on a node's own chain or for the stop-routing rule; both were "
            "written in Rust (verdict_counts.rs, routing_rule.rs in this repo). The port keeps those rules and "
            "adds one thing: the counts are kept per model hash, because eligibility is judged per model. Every "
            "case's answer is stated from the rule in rule_answers/counts.json."
        ),
    },
    "adjudicate": {
        "python": "twin_adjudicator.seal_adjudication_capsule (called by a requester)",
        "rule": "rule 7 (only the referee signs)",
        "why": (
            "Only the referee signs a verdict. The corpus therefore holds adjudicate() to its ruling alone and "
            "never to a record the requester seals: sealing is judged on the referee's side, in the service path."
        ),
    },
}

TIER_NOT_AS_ASKED = "tier_not_as_asked"

# --- the answers the port must give -------------------------------------------
#
# The golden answers are the Python's, except where the Python departs from
# the rules. Each function below states one such departure: given a case and
# the Python's answers, it returns the answers the rule requires. A case it
# changes is listed in ``intended_differences.json`` with the Python's answers.


def _refused(reason: str) -> dict:
    return {"refused": reason, "status": None, "signed_by_node": True,
            "request_digest_is_body_sha256": True, "issued_at_is_now": True}


def _no_threshold(case: dict, answers: list[dict]) -> list[dict]:
    answer = dict(answers[0])
    if "error" not in answer and answer["verdict"] in ("corroborated", "inconclusive") and not answer["referee_called"]:
        answer["verdict"] = "corroborated" if answer["divergence_index"] is None else "inconclusive"
        answer["status"] = twin_adjudicator.status_for_verdict(answer["verdict"])
    return [answer]


def _unknown_weights(case: dict, answers: list[dict]) -> list[dict]:
    answer = answers[0]
    known = all(half["weights_digest"] for half in case["halves"])
    compared = "error" not in answer and answer["no_verdict_reason"] not in ("no_requester_transcript", "not_comparable")
    if known or not compared:
        return answers
    return [
        {
            "verdict": None, "status": None, "no_verdict_reason": "not_comparable", "divergence_index": None,
            "prefix_digest": None, "twin_owner_distinct": None, "weights_digest": None, "referee_called": False,
        }
    ]


def _tier(request: dict):
    """The request's ``selection_tier`` when it is 1 or 2, else ``None``."""
    try:
        parsed = json.loads(body_bytes(request))
    except ValueError:
        return None
    if not referee_service.is_adjudicate_request(parsed):
        return None
    tier = parsed.get("selection_tier")
    return tier if type(tier) is int and tier in (1, 2) else None


def _tier_required(case: dict, answers: list[dict]) -> list[dict]:
    out = []
    for request, answer in zip(case["requests"], answers):
        try:
            adjudicate = referee_service.is_adjudicate_request(json.loads(body_bytes(request)))
        except ValueError:
            adjudicate = False
        if adjudicate and _tier(request) is None:
            answer = {"reply": _refused(referee_service.REASON_REQUEST_MALFORMED), "appended": {}}
        out.append(answer)
    return out


def _sealed_block(case: dict, answers: list[dict]) -> list[dict]:
    tiers = [t for t in map(_tier, case["requests"]) if t is not None]
    answers = copy.deepcopy(answers)
    for answer in answers:
        summaries = [answer["reply"].get("verdict_capsule")]
        summaries += [line["verdict_capsule"] for line in answer["appended"].get(ISSUED, [])]
        for summary in filter(None, summaries):
            block = summary["block"]
            halves = json.loads(body_bytes(case["requests"][0]))["halves"]
            model = halves[0]["capsule"]["model_attestation"]["compute_attestation"]["x-mesh-poc-v1"][
                "serving_provenance"]["model"]["identity_hash"]
            block.update(selection_tier=tiers[0], model_hash=model)
            block.pop("margin", None)
            block.pop("margin_tau", None)
    return answers


def _tier_as_asked(case: dict, answers: list[dict]) -> list[dict]:
    if case["name"] != "hold_refuses_tier_other_than_asked":
        return answers
    return [
        {
            "reply": _refused(TIER_NOT_AS_ASKED),
            "appended": {
                "rejected-record-pushes.jsonl": [
                    {"capsule_id": None, "claimed_sender_peer_id": case["pushes"][0]["sender"],
                     "reason": TIER_NOT_AS_ASKED, "rejected_at": NOW}
                ]
            },
        }
    ]


def _referee_signed(case: dict, answers: list[dict]) -> list[dict]:
    if case["rule"] != "only_referee_signs":
        return answers
    return [{"reply": _refused("verdict_unverified"), "held": False}]


#: Per path: ``(rule, why, the answers the rule requires)``, applied in order.
PORT_RULES = {
    "adjudicate": [
        (
            "rule 1 (trigger: any difference is a difference)",
            "There is no similarity threshold. The Python rules 'corroborated' without a referee when at least "
            "nine tenths of the longer answer's words match before the first difference, and 'inconclusive' "
            "when the share is lower, even for two answers with no words at all. The rule: answers with the same "
            "words are corroborated; any difference at temperature 0 on the same weights means the twins differ, "
            "which without a referee is inconclusive. The port reports and seals no match share.",
            _no_threshold,
        ),
        (
            "rule 3 (eligibility: the same model hash and weights digest)",
            "Twins are compared only when both name the same weights digest. The Python compares, and lets a "
            "referee contradict one of them, when either half names no weights. The rule: not comparable, never a "
            "contradiction.",
            _unknown_weights,
        ),
    ],
    "service": [
        (
            "rule 5 (the tier is sealed in the verdict)",
            "The tier is part of an adjudicate request: the referee seals what the requester states. A request "
            "with no selection_tier, or one that is not 1 or 2, is refused request_malformed. The Python ignores "
            "the member and answers.",
            _tier_required,
        ),
        (
            "rule 5 (the tier is sealed in the verdict) and rule 1 (no similarity threshold)",
            "The port seals two more facts in every verdict: the tier the referee was asked from (selection_tier, "
            "as the requester states it in the adjudicate request) and the model hash the twins served "
            "(model_hash, from their signed records), so a reader can see both. It seals no match share: the "
            "Python's margin and margin_tau are dropped. The Python referee ignores the request's selection_tier "
            "and seals neither of the two facts.",
            _sealed_block,
        ),
    ],
    "hold": [
        (
            "rule 5 (the tier is sealed in the verdict)",
            "The tier is the requester's own statement, sealed by the referee. A verdict that seals a different "
            "tier than this node asked at is not the verdict it asked for, so the port refuses it "
            f"({TIER_NOT_AS_ASKED}) and holds nothing. The Python door does not read the tier and holds it.",
            _tier_as_asked,
        ),
    ],
    "deliver": [
        (
            "rule 7 (only the referee signs)",
            "Only the referee signs a verdict. The Python route holds any well-formed record that carries a "
            "ruling block and cites one of this node's records, whoever sealed it, so a requester (or anyone) "
            "could still hand a node a ruling no referee signed. The port holds a ruling only when the referee "
            "it names signed it with its announced key, the same check the record-push door makes, and "
            "refuses this one verdict_unverified.",
            _referee_signed,
        ),
    ],
    "classify": [],
}


def python_selection_asks_outside() -> list[str]:
    """The select cases where the Python selection, given the same peers,
    asks a node the rules do not allow (or asks one when nobody is eligible).
    It is run over many seeds; one such pick is enough."""
    import random

    from twin_selection import PeerInfo, select_referee

    shown = []
    answers = common.read(common.expected_file("select"))["answers"]
    for case in common.corpus("select")["cases"]:
        digest = case["weights_digest"]
        twin_a, twin_b = (PeerInfo(peer_id=t, weights_digest=digest) for t in case["twins"])
        peers = [PeerInfo(peer_id=p["node_id"], weights_digest=p["weights_digest"]) for p in case["peers"]]
        pool = answers[case["name"]][0]["pool"]
        picks = {select_referee(twin_a, twin_b, peers, rng=random.Random(seed)).chosen_peer_id for seed in range(64)}
        if any(pick is not None and pick not in pool for pick in picks):
            shown.append(case["name"])
    return shown


def port_answers(path: str, case: dict, theirs: list[dict]) -> tuple[list[dict], list[tuple[str, str]]]:
    """``(the answers the rules require for case, the (rule, why) of each
    departure applied)``, given the Python's answers ``theirs``."""
    ours, applied = theirs, []
    for rule, why, required in PORT_RULES[path]:
        changed = required(case, ours)
        if common.canonical(changed) != common.canonical(ours):
            ours = changed
            applied.append((rule, why))
    return ours, applied


def derive(python: dict[str, dict]) -> tuple[dict[str, dict], dict]:
    """``(golden documents by path, the intended-differences document)`` from
    the Python's answers."""
    golden: dict[str, dict] = {}
    cases: dict[str, dict] = {}
    for path in common.PYTHON_PATHS:
        answers: dict[str, list] = {}
        for case in common.corpus(path)["cases"]:
            theirs = python[path]["answers"][case["name"]]
            ours, applied = port_answers(path, case, theirs)
            answers[case["name"]] = ours
            if applied:
                cases[f"{path}/{case['name']}"] = {
                    "rule": "; ".join(rule for rule, _ in applied),
                    "why": " ".join(why for _, why in applied),
                    "python_answers": theirs,
                }
        golden[path] = {"v": 1, "path": path, "source": "the Python reference, and the rules where it departs",
                        "answers": answers}
    intended = {
        "v": 1,
        "note": (
            "Where the Python reference does not follow the rules, so its answer is not the golden answer. "
            "'paths' lists whole paths where a Python module exists but is not the reference: every answer there "
            "is stated from the rules. 'cases' lists single cases of a Python-judged path: the golden file holds "
            "the answer the rule requires, and 'python_answers' records what the Python answers instead."
        ),
        "paths": {
            **PATH_DIFFERENCES,
            "select": {**PATH_DIFFERENCES["select"], "shown_by": python_selection_asks_outside()},
        },
        "cases": cases,
    }
    return golden, intended


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--out", type=Path, help="write every Python-judged path's answers here")
    group.add_argument("--golden", action="store_true", help="rewrite the golden answers and what follows from them")
    args = parser.parse_args()
    answers = run_all()
    if args.out:
        doc = {"v": 1, "implementation": IMPLEMENTATION, "paths": {p: a["answers"] for p, a in answers.items()}}
        args.out.write_text(json.dumps(doc, sort_keys=True) + "\n", encoding="utf-8")
        print(f"wrote {sum(len(a['answers']) for a in answers.values())} case answers to {args.out}")
        return
    golden, intended = derive(answers)
    for path, doc in golden.items():
        common.write_answers(common.GOLDEN_DIR / f"{path}.json", doc)
        print(f"wrote {len(doc['answers']):3d} answers to golden/{path}.json")
    common.parity_format.write(common.INTENDED, intended, "cases")
    print(f"wrote {len(intended['cases'])} case and {len(intended['paths'])} path differences to {common.INTENDED.name}")
    # Imported here: referee_mutants runs this module's paths with a fault.
    import referee_mutants

    referee_mutants.write()
    print(f"wrote {len(referee_mutants.MUTANTS)} mutants to {common.MUTANTS.name}")


if __name__ == "__main__":
    main()
