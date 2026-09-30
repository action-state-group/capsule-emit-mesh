# SPDX-License-Identifier: Apache-2.0
"""Build the referee parity corpus: ``corpus/*.json`` and ``rule_answers/*.json``.

Eight paths (see ``README.md``). Five are judged against the Python reference
and get their inputs here; ``referee_python.py`` writes their answers. Three
have no Python reference that follows the rules, so each of their cases states
its expected answer here, by hand, from the rule it names.

Public material only: signed records, public key ids, plain facts. Every
node is ``node-<letter>`` and signs with its fixed test key, and every record
is sealed at a fixed time, so a rebuild with the same library versions gives
the same files byte for byte.

    python tests/parity/referee/build_referee_corpus.py
"""
from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timedelta

import referee_common as common
from referee_common import NOW, SEALED_AT, Node, key_id

from agent_action_capsule.contracts import Disposition, EffectRecord  # noqa: E402
from agent_action_capsule.emit import emit  # noqa: E402
from capsule_emit.canonicalization import compute_capsule_id  # noqa: E402
from capsule_emit.signing import sign_producer_envelope  # noqa: E402

from capsule_sidecar import digest_json  # noqa: E402
from referee_service import handle_adjudicate_request  # noqa: E402

A, B, C, D, E, F, G = (f"node-{x}" for x in "abcdefg")
#: The requester that ran the twins.
Q = "node-q"
#: An announced node that is no part of the exchange.
X = "node-x"
#: A node that announced no key.
Z = "node-z"

REG = {n: key_id(n) for n in (A, B, C, D, Q, X)}


def _hex(label: str) -> str:
    return hashlib.sha256(f"referee-parity/{label}".encode()).hexdigest()


REQ = _hex("request-1")
REQ_OTHER = _hex("request-2")
MODEL_X, MODEL_Y = _hex("model-x"), _hex("model-y")
W1, W2 = _hex("weights-1"), _hex("weights-2")

PROMPT = {"messages": [{"role": "user", "content": "List the first five counting numbers."}]}
HONEST = "1, 2, 3, 4, 5"
FLIPPED = "1, 2, 3, 999 5"
OTHER = "1, 2, 3, 7, 5"
BRACKET = "bracket-1"

_ABSENT = object()


def body(text: str) -> dict:
    return {"choices": [{"message": {"role": "assistant", "content": text}}]}


def _sign(capsule: dict, node: str) -> dict:
    capsule["signature"], capsule["key_id"] = sign_producer_envelope(common.signer(node), capsule["capsule_id"])
    return capsule


def served(
    node: str,
    text: str,
    label: str,
    *,
    request_digest: str = REQ,
    weights: str | None = W1,
    model: str = MODEL_X,
    signed_by: str | None = None,
    served_by=_ABSENT,
    role: str | None = None,
    decoding: dict | None = None,
    generation: dict | None = None,
    owner: str | None = None,
) -> dict:
    """A node's own served record of ``text``, signed with its test key."""
    provenance: dict = {"model": {"identity_hash": model, "weights_digest": weights}}
    server = node if served_by is _ABSENT else served_by
    if server is not None:
        provenance["served_by_node_id"] = server
    if role:
        provenance["role"] = role
    poc: dict = {"role": "served", "serving_provenance": provenance}
    if generation:
        poc["generation_parameters"] = generation
    attestation: dict = {"x-mesh-poc-v1": poc}
    if decoding:
        attestation["decoding"] = decoding
    if owner:
        attestation["owner"] = {"owner_id": owner}
    capsule = emit(
        action_id=f"serve_exchange/{label}",
        timestamp=SEALED_AT,
        action_type="decide",
        operator="",
        developer="",
        compute_attestation=attestation,
        effect=EffectRecord(
            status="confirmed",
            type="inference_completion",
            request_digest=request_digest,
            response_digest=digest_json(body(text)),
        ),
        disposition=Disposition(decision="accept", approver="policy", human_disposed=False, verdict_class="confirmed"),
        tool_name="serve_exchange",
    )
    return _sign(capsule, signed_by or node)


def resealed(capsule: dict, node: str, change) -> dict:
    """``capsule`` with ``change`` applied, its id recomputed, signed by ``node``."""
    out = copy.deepcopy(capsule)
    change(out)
    out.pop("signature", None)
    out.pop("key_id", None)
    out["capsule_id"] = compute_capsule_id(out)
    return _sign(out, node)


def block_of(capsule: dict) -> dict:
    return capsule["model_attestation"]["compute_attestation"]["adjudication"]


def names(cases: list[dict]) -> list[dict]:
    seen = [c["name"] for c in cases]
    assert len(seen) == len(set(seen)), "case names must be unique"
    return cases


# --- adjudicate: two halves, and the ruling on them ---------------------------


def half(capsule: dict, text: str | None, *, node: str | None, weights: str | None = W1, request=PROMPT, **more):
    entry = {
        "capsule": capsule,
        "request_body": request,
        "response_body": None if text is None else body(text),
        "node_id": node,
        "weights_digest": weights,
    }
    entry.update(more)
    return entry


def build_adjudicate() -> list[dict]:
    cases: list[dict] = []

    def add(name, rule, covers, half_a, half_b, referee=None):
        cases.append({"name": name, "rule": rule, "covers": covers, "halves": [half_a, half_b], "referee": referee})

    def twins(name, text_a=HONEST, text_b=FLIPPED, **kw):
        return served(A, text_a, f"{name}-a", **kw), served(B, text_b, f"{name}-b", **kw)

    def answer(text, node=C):
        return {"node_id": node, "answer_text": text}

    a, b = twins("agree", HONEST, HONEST)
    add("agree_identical", "trigger", "the same answer is corroborated; the referee is never called",
        half(a, HONEST, node=A), half(b, HONEST, node=B), answer(HONEST))
    a, b = twins("agree_spacing", HONEST, "1,  2,\n3, 4, 5")
    add("agree_whitespace_only", "trigger", "answers that differ only in spacing are the same words",
        half(a, HONEST, node=A), half(b, "1,  2,\n3, 4, 5", node=B), answer(HONEST))
    a, b = twins("both_empty", "", "")
    add("both_answers_empty", "trigger", "two empty answers have no words to compare",
        half(a, "", node=A), half(b, "", node=B), answer(HONEST))
    a, b = twins("differ_alone")
    add("differ_no_referee", "trigger", "differing answers with no referee are inconclusive, never a contradiction",
        half(a, HONEST, node=A), half(b, FLIPPED, node=B))
    long_a = "one two three four five six seven eight nine ten eleven"
    long_b = "one two three four five six seven eight nine ten twelve"
    a, b = twins("within_margin", long_a, long_b)
    add("differ_last_word_no_referee", "trigger", "one late differing word, no referee",
        half(a, long_a, node=A), half(b, long_b, node=B))
    a, b = twins("within_margin_referee", long_a, long_b)
    add("differ_last_word_referee_decides", "trigger", "any difference calls the referee, however late",
        half(a, long_a, node=A), half(b, long_b, node=B), answer(long_a))

    a, b = twins("matches_a")
    add("referee_matches_a", "verdict", "the referee's word at the difference is A's: B is contradicted",
        half(a, HONEST, node=A), half(b, FLIPPED, node=B), answer(HONEST))
    a, b = twins("matches_b", FLIPPED, HONEST)
    add("referee_matches_b", "verdict", "the referee's word at the difference is B's: A is contradicted",
        half(a, FLIPPED, node=A), half(b, HONEST, node=B), answer(HONEST))
    a, b = twins("matches_neither")
    add("referee_matches_neither", "verdict", "a third answer settles nothing",
        half(a, HONEST, node=A), half(b, FLIPPED, node=B), answer(OTHER))
    a, b = twins("prefix_not_repeated")
    add("referee_does_not_repeat_the_agreed_words", "verdict",
        "a re-answer that departs before the difference is not read at it",
        half(a, HONEST, node=A), half(b, FLIPPED, node=B), answer("0, 2, 3, 4, 5"))
    a, b = twins("too_short")
    add("referee_answer_stops_before_the_difference", "verdict", "a re-answer with no word at the difference",
        half(a, HONEST, node=A), half(b, FLIPPED, node=B), answer("1, 2, 3,"))
    a, b = twins("first_word", "yes it is", "no it is")
    add("differ_at_the_first_word", "verdict", "no agreed words at all; the referee's first word decides",
        half(a, "yes it is", node=A), half(b, "no it is", node=B), answer("yes it is"))
    a, b = twins("prefix_of", "1, 2, 3,", HONEST)
    add("one_answer_is_the_start_of_the_other", "verdict", "A stopped early; the referee went on as B did",
        half(a, "1, 2, 3,", node=A), half(b, HONEST, node=B), answer(HONEST))
    a, b = twins("no_request")
    add("no_disclosed_request", "verdict", "with no request to re-answer, the referee's first word is read",
        half(a, HONEST, node=A, request={}), half(b, FLIPPED, node=B, request={}), answer("4,"))
    a, b = twins("unreachable")
    add("referee_unreachable", "never_contradicted", "a referee that does not answer leaves no verdict",
        half(a, HONEST, node=A), half(b, FLIPPED, node=B), {"node_id": C, "unreachable": True})
    a, b = twins("referee_is_twin")
    add("referee_is_a_twin", "eligibility", "a twin is never asked to referee its own pair",
        half(a, HONEST, node=A), half(b, FLIPPED, node=B), answer(HONEST, node=A))

    a, b = twins("forged_a")
    add("forged_half_a", "half", "a half changed after sealing is refused, not ruled on",
        half({**a, "operator": "someone-else"}, HONEST, node=A), half(b, FLIPPED, node=B), answer(HONEST))
    a, b = twins("forged_b")
    add("forged_half_b", "half", "the second half changed after sealing",
        half(a, HONEST, node=A), half({**b, "capsule_id": "0" * 64}, FLIPPED, node=B), answer(HONEST))
    a, b = twins("preimage")
    add("answer_is_not_the_signed_body", "half", "an answer that does not hash to the record's response digest",
        half(a, HONEST, node=A), half(b, HONEST, node=B), answer(HONEST))
    a, b = twins("text_swap")
    add("text_is_not_the_signed_bodys_text", "half", "a separate text beside the signed body is refused",
        half(a, HONEST, node=A), half(b, FLIPPED, node=B, response_text=HONEST), answer(HONEST))
    a = served(A, HONEST, "provider-a", role="provider")
    b = served(B, FLIPPED, "provider-b")
    add("provider_half_without_a_body", "half", "a provider's half with no answer held: nothing to compare",
        half(a, None, node=A), half(b, FLIPPED, node=B), answer(HONEST))

    a, b = twins("sampled_decoding", decoding={"temperature": "0.7", "seed": 1})
    add("sampled_sealed_decoding", "trigger", "a sealed temperature above 0: not comparable, never a contradiction",
        half(a, HONEST, node=A), half(b, FLIPPED, node=B), answer(HONEST))
    a, b = twins("sampled_generation", generation={"temperature": "0.2"})
    add("sampled_host_parameters", "trigger", "the host's generation parameters say sampled",
        half(a, HONEST, node=A), half(b, FLIPPED, node=B), answer(HONEST))
    a, b = twins("sampled_request")
    hot = {**PROMPT, "temperature": 0.7}
    add("sampled_request", "trigger", "the disclosed request asked for a temperature above 0",
        half(a, HONEST, node=A, request=hot), half(b, FLIPPED, node=B, request=hot), answer(HONEST))
    a, b = twins("sampled_one")
    add("one_half_sampled", "trigger", "one sampled half is enough",
        half(a, HONEST, node=A), half(b, FLIPPED, node=B, request=hot), answer(HONEST))
    a, b = twins("greedy", decoding={"temperature": "0", "seed": 1})
    cold = {**PROMPT, "temperature": 0}
    add("temperature_zero_is_compared", "trigger", "temperature 0, sealed and asked, is compared as usual",
        half(a, HONEST, node=A, request=cold), half(b, FLIPPED, node=B, request=cold), answer(HONEST))

    a = served(A, HONEST, "weights-a")
    b = served(B, FLIPPED, "weights-b", weights=W2)
    add("weights_differ", "eligibility", "twins on different weights are not adjudicated",
        half(a, HONEST, node=A), half(b, FLIPPED, node=B, weights=W2), answer(HONEST))
    a = served(A, HONEST, "weights-unknown-a")
    b = served(B, FLIPPED, "weights-unknown-b", weights=None)
    add("weights_unknown_on_one_side", "eligibility", "one half names no weights: compared, no shared digest claimed",
        half(a, HONEST, node=A), half(b, FLIPPED, node=B, weights=None), answer(HONEST))
    a = served(A, HONEST, "same-node-1")
    b = served(A, FLIPPED, "same-node-2")
    add("both_halves_from_one_node", "eligibility", "one node's two answers are not a twin pair",
        half(a, HONEST, node=A), half(b, FLIPPED, node=A), answer(HONEST))
    a, b = twins("node_absent")
    add("half_names_no_node", "eligibility", "a half with no serving node is never treated as independent",
        half(a, HONEST, node=A), half(b, FLIPPED, node=None), answer(HONEST))
    return names(cases)


# --- service: the referee answers an adjudicate request -----------------------


def adjudicate_request(half_a, text_a, half_b, text_b, referee_text=HONEST, *, bracket=BRACKET, tier=1, prompt=PROMPT):
    request: dict = {
        "subject": {"kind": "adjudicate"},
        "halves": [
            {"capsule": half_a, "request_body": prompt, "response_body": body(text_a)},
            {"capsule": half_b, "request_body": prompt, "response_body": body(text_b)},
        ],
    }
    if bracket is not None:
        request["twin_bracket_id"] = bracket
    if tier is not None:
        request["selection_tier"] = tier
    if referee_text is not None:
        request["referee_answer"] = {"request_body": prompt, "response_body": body(referee_text)}
    return request


def send(request) -> dict:
    """One request body: JSON text, or raw text for a body that is not JSON."""
    return {"body": request if isinstance(request, str) else json.dumps(request)}


def build_service() -> list[dict]:
    cases: list[dict] = []

    def add(name, rule, covers, requests, *, own=(), node=C, peer_keys=REG):
        cases.append(
            {
                "name": name,
                "rule": rule,
                "covers": covers,
                "node": {"id": node, "peer_keys_env": json.dumps(peer_keys), "files": {"capsules.jsonl": list(own)}},
                "requests": [send(r) for r in requests],
            }
        )

    def exchange(name, text_a=HONEST, text_b=FLIPPED, referee_text=HONEST, **kw):
        return (
            served(A, text_a, f"{name}-a", **kw),
            served(B, text_b, f"{name}-b", **kw),
            served(C, referee_text, f"{name}-c", **kw),
        )

    a, b, c = exchange("contradicts_b")
    add("contradicts_b", "tier_sealed", "the referee's answer is A's: a signed contradiction of B, citing its own record",
        [adjudicate_request(a, HONEST, b, FLIPPED)], own=[c])
    a, b, c = exchange("contradicts_a", FLIPPED, HONEST)
    add("contradicts_a", "verdict", "the referee's answer is B's: a signed contradiction of A",
        [adjudicate_request(a, FLIPPED, b, HONEST)], own=[c])
    a, b, c = exchange("tier_two")
    add("tier_two_referee", "tier_sealed", "a referee asked from the second tier",
        [adjudicate_request(a, HONEST, b, FLIPPED, tier=2)], own=[c])
    a, b, c = exchange("neither", referee_text=OTHER)
    add("answer_matches_neither", "verdict", "a third answer is a signed inconclusive",
        [adjudicate_request(a, HONEST, b, FLIPPED, OTHER)], own=[c])
    a, b, c = exchange("agree", HONEST, HONEST)
    add("twins_agree_no_answer", "trigger", "agreeing twins are corroborated with no referee answer",
        [adjudicate_request(a, HONEST, b, HONEST, None)], own=[c])
    add("twins_agree_answer_unused", "trigger", "a referee answer sent with agreeing twins decides nothing and is not cited",
        [adjudicate_request(a, HONEST, b, HONEST)], own=[c])
    a, b, c = exchange("no_bracket")
    add("no_bracket_id", "verdict", "a request with no bracket id seals none",
        [adjudicate_request(a, HONEST, b, FLIPPED, bracket=None)], own=[c])

    a, b, c = exchange("repeat")
    again = adjudicate_request(a, HONEST, b, FLIPPED)
    add("repeat_returns_the_issued_verdict", "cap", "the same pair asked twice gets the verdict already issued",
        [again, again], own=[c])
    a, b, c = exchange("repeat_swapped")
    add("repeat_with_the_halves_swapped", "cap", "the pair in the other order is the same pair",
        [adjudicate_request(a, HONEST, b, FLIPPED), adjudicate_request(b, FLIPPED, a, HONEST)], own=[c])

    a, b, c = exchange("text_rewritten")
    add("answer_not_covered_by_the_signature", "half", "B's real record with its answer rewritten",
        [adjudicate_request(a, HONEST, b, HONEST.replace("5", "6"))], own=[c])
    a, b, c = exchange("unannounced")
    add("half_signed_by_an_unannounced_key", "half", "a half signed by a key B never announced",
        [adjudicate_request(a, HONEST, served(B, FLIPPED, "unannounced-forged", signed_by=Z), FLIPPED)], own=[c])
    add("half_names_no_server", "half", "a half that names no serving node",
        [adjudicate_request(a, HONEST, served(B, FLIPPED, "unannounced-noserver", served_by=None), FLIPPED)], own=[c])
    add("half_is_not_a_record", "half", "a half whose record is not an object",
        [{**adjudicate_request(a, HONEST, b, FLIPPED), "halves": [{"capsule": "x"}, {"capsule": "y"}]}], own=[c])

    a, b, _ = exchange("never_served")
    add("answer_the_referee_never_served", "never_contradicted", "the referee holds no record of the answer sent",
        [adjudicate_request(a, HONEST, b, FLIPPED)])
    add("answer_record_signed_by_another_key", "never_contradicted", "a record of the answer under another node's key",
        [adjudicate_request(a, HONEST, b, FLIPPED)], own=[served(C, HONEST, "never_served-other-key", signed_by=A)])
    add("answer_record_names_another_server", "never_contradicted", "the referee's key on a record naming another server",
        [adjudicate_request(a, HONEST, b, FLIPPED)], own=[served(C, HONEST, "never_served-other-server", served_by=A)])
    a, b, c = exchange("no_answer")
    add("differing_twins_without_an_answer", "never_contradicted", "differing twins and no referee answer: no verdict",
        [adjudicate_request(a, HONEST, b, FLIPPED, None)], own=[c])

    a, b, _ = exchange("twin_referee")
    add("a_twin_cannot_referee", "eligibility", "the node asked is one of the twins",
        [adjudicate_request(a, HONEST, b, FLIPPED)], own=[a, served(A, HONEST, "twin_referee-own")], node=A)
    a = served(A, HONEST, "other_request-a")
    b = served(B, FLIPPED, "other_request-b", request_digest=REQ_OTHER)
    c = served(C, HONEST, "other_request-c")
    add("twins_answered_different_requests", "eligibility", "the halves' signed request digests differ",
        [adjudicate_request(a, HONEST, b, FLIPPED)], own=[c])
    a, b, c = exchange("unnamed")
    add("referee_not_announced", "eligibility", "a node whose own key is not announced signs nothing",
        [adjudicate_request(a, HONEST, b, FLIPPED)], own=[c], peer_keys={n: k for n, k in REG.items() if n != C})
    a = served(A, HONEST, "one_node-1")
    a2 = served(A, FLIPPED, "one_node-2")
    c = served(C, HONEST, "one_node-c")
    add("both_halves_from_one_node", "eligibility", "one node's two answers are not a twin pair",
        [adjudicate_request(a, HONEST, a2, FLIPPED)], own=[c])

    a, b, c = exchange("malformed")
    good = adjudicate_request(a, HONEST, b, FLIPPED)
    add("malformed_requests", "half", "bodies that are not an adjudicate request are refused, never raised on",
        ["not json", {}, {"subject": {"kind": "record"}}, {**good, "halves": []}, {**good, "halves": good["halves"] * 2},
         {**good, "referee_answer": "text"}, {**good, "referee_answer": {"response_body": "text"}},
         {**good, "twin_bracket_id": 7}], own=[c])

    a, b, c = exchange("sampled")
    hot = {**PROMPT, "temperature": 0.7}
    add("sampled_twins", "trigger", "sampled twins get a signed not-comparable ruling, never a contradiction",
        [adjudicate_request(a, HONEST, b, FLIPPED, prompt=hot)], own=[c])
    a = served(A, HONEST, "weights_differ-a")
    b = served(B, FLIPPED, "weights_differ-b", weights=W2)
    c = served(C, HONEST, "weights_differ-c")
    add("weights_differ", "eligibility", "twins on different weights: not comparable",
        [adjudicate_request(a, HONEST, b, FLIPPED)], own=[c])
    add("weights_differ_and_forged", "half", "a forged half is refused even when the weights differ",
        [adjudicate_request(a, HONEST, b, HONEST.replace("5", "6"))], own=[c])
    b = served(B, FLIPPED, "weights_unknown-b", weights=None)
    add("weights_unknown", "eligibility", "a half that names no weights: not comparable",
        [adjudicate_request(a, HONEST, b, FLIPPED)], own=[c])
    return names(cases)


# --- verdicts, for the paths that receive one ---------------------------------


def issued_verdict(label, *, text_a=HONEST, text_b=FLIPPED, referee_text=HONEST, referee=C, tier=1, prompt=PROMPT,
                   weights_b=W1):
    """A referee-signed verdict on a fresh twin pair, as the port seals one:
    the Python referee's own block plus the tier and the model hash, sealed
    at the fixed time. Returns ``(verdict, half A, half B)``."""
    half_a = served(A, text_a, f"{label}-a")
    half_b = served(B, text_b, f"{label}-b", weights=weights_b)
    record = served(referee, referee_text, f"{label}-r")
    node = {"id": referee, "peer_keys_env": json.dumps({**REG, referee: key_id(referee)}),
            "files": {"capsules.jsonl": [record]}}
    request = adjudicate_request(half_a, text_a, half_b, text_b, referee_text, tier=tier, prompt=prompt)
    with Node(node) as n:
        reply = handle_adjudicate_request(n.state, json.dumps(request).encode("utf-8"))
    assert "verdict_capsule" in reply, reply
    block = dict(block_of(reply["verdict_capsule"]))
    block["selection_tier"] = tier
    block["model_hash"] = MODEL_X
    return verdict_capsule(block, label, referee), half_a, half_b


def verdict_capsule(block: dict, label: str, referee: str) -> dict:
    capsule = emit(
        action_id=f"adjudicate/{label}",
        timestamp=SEALED_AT,
        action_type="decide",
        operator="",
        developer="",
        compute_attestation={"epistemic_type": "adjudication", "adjudication": block},
        disposition=Disposition(decision="accept", approver="policy", human_disposed=False, verdict_class="assessed"),
        prior_capsule_id=block["half_a_capsule_id"],
        chain_relation="adjudicates",
        domain="action",
        provenance="referee",
        tool_name="adjudicate",
    )
    return _sign(capsule, referee)


def reblock(signed_verdict: dict, node: str, **changes) -> dict:
    """A verdict with its ruling block changed, genuinely re-sealed by ``node``."""
    return resealed(signed_verdict, node, lambda c: block_of(c).update(changes))


def delivery(verdict, sender=C, **more) -> dict:
    return {"sender": sender, "body": json.dumps({"adjudication_delivery": 1, "verdict_capsule": verdict, **more})}


def asked_line(referee: str, pair: list[str], tier: int = 1) -> dict:
    return {"referee": referee, "halves": pair, "twin_bracket_id": BRACKET, "selection_tier": tier, "asked_at": SEALED_AT}


# --- hold: a node receives a delivered verdict --------------------------------


def build_hold() -> list[dict]:
    cases: list[dict] = []

    def add(name, rule, covers, pushes, *, node, own=(), received=(), requested=(), peer_keys=REG, policy=None):
        files = {"capsules.jsonl": list(own)}
        if received:
            files["received-capsules.jsonl"] = list(received)
        if requested:
            files["requested-adjudications.jsonl"] = list(requested)
        cases.append(
            {
                "name": name,
                "rule": rule,
                "covers": covers,
                "node": {"id": node, "peer_keys_env": json.dumps(peer_keys), "record_at_completion": policy, "files": files},
                "pushes": pushes,
            }
        )

    def requester(name, rule, covers, verdict, half_a, half_b, *, asked=_ABSENT, holds=None, tier=1, pushes=None):
        pair = [half_a["capsule_id"], half_b["capsule_id"]]
        line = [asked_line(C, pair, tier)] if asked is _ABSENT else asked
        add(name, rule, covers, pushes or [delivery(verdict)], node=Q,
            received=[half_a, half_b] if holds is None else holds, requested=line)

    v, a, b = issued_verdict("provider")
    add("provider_holds_a_verdict_about_its_record", "delivery", "a judged provider holds the verdict contradicting it",
        [delivery(v)], node=B, own=[b])
    add("other_provider_holds_it_too", "delivery", "the other twin holds the same verdict",
        [delivery(v)], node=A, own=[a])
    add("delivered_twice", "delivery", "the same verdict again is answered from what is held",
        [delivery(v), delivery(v, sender=Q)], node=B, own=[b])
    add("holds_nothing_it_concerns", "delivery", "a node that holds neither half refuses it",
        [delivery(v)], node=X)
    add("policy_off", "delivery", "record_at_completion off declines a delivery too",
        [delivery(v)], node=B, own=[b], policy="off")
    add("no_sender", "delivery", "a delivery with no sender id is refused",
        [delivery(v, sender=None)], node=B, own=[b])
    add("malformed_delivery", "delivery", "an extra member, or another version, is not a delivery",
        [delivery(v, note="x"), {"sender": C, "body": json.dumps({"adjudication_delivery": 2, "verdict_capsule": v})}],
        node=B, own=[b])

    v, a, b = issued_verdict("requester")
    requester("requester_holds_a_verdict_it_asked_for", "delivery", "the requester asked this referee about this pair",
              v, a, b)
    requester("requester_did_not_ask", "delivery", "a verdict about records the requester holds, from a referee nobody asked",
              v, a, b, asked=[])
    requester("requester_asked_another_referee", "delivery", "the requester asked a different referee about the pair",
              v, a, b, asked=[asked_line(D, [a["capsule_id"], b["capsule_id"]])])
    requester("requester_asked_about_another_pair", "delivery", "the requester asked this referee about other halves",
              v, a, b, asked=[asked_line(C, [a["capsule_id"], _hex("another-half")])])
    requester("requester_holds_one_half", "delivery", "the requester must hold both halves it asked about",
              v, a, b, holds=[a])
    forged = [reblock(v, X, referee_node_id=X, half_b_capsule_id=_hex(f"made-up-{n}")) for n in range(3)]
    requester("announced_peer_mints_verdicts", "delivery",
              "an announced node nobody asked signs contradictions about a held record: none is held",
              v, a, b, pushes=[delivery(f, sender=X) for f in forged])
    second = reblock(v, C, verdict="inconclusive", status="UNKNOWN")
    requester("second_verdict_on_the_pair", "delivery", "one verdict per referee and pair; the first again is answered",
              v, a, b, pushes=[delivery(v), delivery(second), delivery(v)])
    requested = served(Q, HONEST, "requester-own", served_by=A)
    add("requesters_own_requested_record", "delivery",
        "the requester's own record of asking names the provider as server: not a record it served",
        [delivery(reblock(v, C, half_a_capsule_id=requested["capsule_id"]))], node=Q, own=[requested])

    v, a, b = issued_verdict("provider_cap")
    first = reblock(v, X, referee_node_id=X, half_a_capsule_id=_hex("pair-1"))
    other = reblock(v, X, referee_node_id=X, half_a_capsule_id=_hex("pair-2"))
    add("second_verdict_on_a_providers_record", "delivery", "one verdict per referee and own record on a provider",
        [delivery(first, sender=X), delivery(other, sender=X)], node=B, own=[b])
    add("verdict_about_a_record_merely_held", "delivery", "a verdict about B's record and a made-up one is not A's",
        [delivery(reblock(v, C, half_a_capsule_id=_hex("pair-3")))], node=A, own=[a])

    v, a, b = issued_verdict("misattributed")
    swapped = reblock(v, C, half_a_node_id=B, half_b_node_id=A, verdict=f"contradicted:{A}")
    requester("halves_pinned_on_the_wrong_nodes", "delivery", "a verdict cannot pin one node's record on another",
              swapped, a, b)
    add("own_half_pinned_on_the_other_node", "delivery", "a provider sees its own record named as the other twin's",
        [delivery(swapped)], node=B, own=[b])

    v, a, b = issued_verdict("unverified")
    unverified = [
        ("signed_by_another_node", "the verdict names C but A signed it", _sign(dict(v), A)),
        ("ruling_changed_after_signing", "the ruling edited after the referee signed",
         _edit(v, verdict=f"contradicted:{A}")),
        ("unsigned", "a verdict with no signature", {k: val for k, val in v.items() if k not in ("signature", "key_id")}),
        ("contradicts_a_node_outside_the_pair", "genuinely signed, but it contradicts a node that was not a twin",
         reblock(v, C, verdict=f"contradicted:{X}")),
        ("referee_is_a_twin", "genuinely signed by a node the verdict also names as a twin",
         reblock(v, A, referee_node_id=A)),
        ("referee_not_announced", "signed by a node that announced no key", reblock(v, Z, referee_node_id=Z)),
        ("both_halves_named_for_one_node", "both halves attributed to one node", reblock(v, C, half_b_node_id=A)),
        ("unknown_ruling", "a ruling outside the four", reblock(v, C, verdict="undecided")),
        ("names_no_referee", "a ruling block that names no referee", resealed(v, C, lambda c: block_of(c).pop("referee_node_id"))),
    ]
    for name, covers, bad in unverified:
        add(f"unverified_{name}", "delivery", covers, [delivery(bad)], node=B, own=[b])
    add("unverified_not_a_record", "delivery", "the delivered verdict is not an object",
        [{"sender": C, "body": json.dumps({"adjudication_delivery": 1, "verdict_capsule": "x"})}], node=B, own=[b])

    v, a, b = issued_verdict("tier")
    requester("verdict_carries_selection_tier", "tier_sealed", "the tier the requester asked at is sealed in the verdict it holds",
              v, a, b)
    add("altered_tier_fails_verification", "tier_sealed", "the sealed tier changed after signing: the verdict no longer verifies",
        [delivery(_edit(v, selection_tier=2))], node=Q, received=[a, b],
        requested=[asked_line(C, [a["capsule_id"], b["capsule_id"]])])
    requester("hold_refuses_tier_other_than_asked", "tier_sealed",
              "genuinely signed at tier 1, but this node asked at tier 2", v, a, b, tier=2)

    v, a, b = issued_verdict("sampled", prompt={**PROMPT, "temperature": 0.7})
    add("not_comparable_ruling_is_held", "never_contradicted", "a not-comparable ruling is delivered and held like any other",
        [delivery(v)], node=B, own=[b])
    return names(cases)


def _edit(signed_verdict: dict, **changes) -> dict:
    """A verdict with its ruling block edited and nothing re-sealed."""
    out = copy.deepcopy(signed_verdict)
    block_of(out).update(changes)
    return out


# --- deliver: the /evidence/deliver route -------------------------------------


def build_deliver() -> list[dict]:
    cases: list[dict] = []

    def add(name, rule, covers, bodies, *, own=(), node=B):
        cases.append(
            {
                "name": name,
                "rule": rule,
                "covers": covers,
                "node": {"id": node, "peer_keys_env": json.dumps(REG), "files": {"capsules.jsonl": list(own)}},
                "deliveries": [{"body": b if isinstance(b, str) else json.dumps(b, sort_keys=True)} for b in bodies],
            }
        )

    v, a, b = issued_verdict("deliver")
    add("cites_own_half", "delivery", "a referee-signed verdict citing this node's record", [v], own=[b])
    add("cites_no_record_of_this_node", "delivery", "a verdict about other nodes' records", [v], node=X)
    add("not_json", "delivery", "a body that is not JSON", ["not json"], own=[b])
    add("no_capsule_id", "delivery", "a body with no capsule id", [{"note": "x"}], own=[b])
    add("fails_verification", "delivery", "a verdict changed after sealing", [_edit(v, verdict="corroborated")], own=[b])
    add("cites_nothing", "delivery", "a record with no ruling block cites nothing", [a], own=[b])
    owned = served(B, FLIPPED, "deliver-owned-b", owner=B)
    about_owned = reblock(v, C, half_b_capsule_id=owned["capsule_id"])
    add("contradicted_node_declines", "delivery", "a node named as contradicted declines to hold the verdict",
        [about_owned], own=[owned])
    unsigned = {k: val for k, val in v.items() if k not in ("signature", "key_id")}
    add("verdict_the_referee_did_not_sign", "only_referee_signs", "a ruling no referee signed, citing this node's record",
        [unsigned], own=[b])
    by_requester = reblock(v, Q, verdict="corroborated", status="SATISFIED")
    add("verdict_signed_by_the_requester", "only_referee_signs", "a ruling naming C as referee, sealed by the requester",
        [by_requester], own=[b])
    return names(cases)


# --- classify: verdicts a node's references hold about it ---------------------


def ack_refused(verdict: dict, label: str, *, cited: str | None = None) -> dict:
    """The requester's record of a refused delivery of ``verdict``."""
    block = {
        "adjudication_capsule_id": cited or verdict["capsule_id"],
        "verdict": block_of(verdict)["verdict"],
        "counterparty_ref": block_of(verdict)["verdict"].partition(":")[2] or None,
        "refusal": {"reason": "policy_decline"},
    }
    capsule = emit(
        action_id=f"adjudication_ack_refused/{label}",
        timestamp=SEALED_AT,
        action_type="fyi",
        operator="",
        developer="",
        compute_attestation={"adjudication_ack_refused": block},
        prior_capsule_id=block["adjudication_capsule_id"],
        chain_relation="adjudication_ack_refused",
        domain="action",
        provenance="referee",
        tool_name="adjudication_ack_refused",
    )
    return _sign(capsule, Q)


def build_classify() -> list[dict]:
    cases: list[dict] = []

    def add(name, rule, covers, receipts, *, x=B, peer_keys=REG):
        cases.append({"name": name, "rule": rule, "covers": covers, "x": x,
                      "peer_keys_env": json.dumps(peer_keys), "receipts": receipts})

    v, a, b = issued_verdict("classify")
    add("contradiction_of_x", "counts", "a verified contradiction naming X", [v])
    add("contradiction_of_the_other_twin", "counts", "a contradiction of the other twin corroborates X", [v], x=A)
    add("x_was_not_judged", "counts", "a verdict about other nodes says nothing about X", [v], x=D)
    add("inconclusive", "counts", "an inconclusive ruling", [reblock(v, C, verdict="inconclusive", status="UNKNOWN")])
    add("corroborated", "counts", "a corroboration", [reblock(v, C, verdict="corroborated", status="SATISFIED")])
    add("not_comparable", "counts", "a not-comparable ruling", [reblock(v, C, verdict="not_comparable", status="UNKNOWN")])
    add("held_by_many_references", "counts", "one verdict counts once, however many references hold it", [v, v, v])
    add("one_referee_one_pair", "counts", "one referee counts once per pair, whatever it signs",
        [v, reblock(v, C, verdict="inconclusive", status="UNKNOWN"),
         reblock(v, C, half_a_capsule_id=b["capsule_id"], half_b_capsule_id=a["capsule_id"],
                 half_a_node_id=B, half_b_node_id=A)])
    add("two_referees_one_pair", "counts", "two referees on one pair count twice",
        [v, reblock(v, D, referee_node_id=D)])
    add("one_referee_two_pairs", "counts", "one referee on two pairs counts twice",
        [v, reblock(v, C, half_a_capsule_id=_hex("classify-pair-2"))])

    unsigned = {k: val for k, val in v.items() if k not in ("signature", "key_id")}
    add("forged_unsigned", "counts", "a ruling block with no referee signature counts nowhere", [unsigned])
    add("forged_unannounced_key", "counts", "signed by a key the named referee never announced",
        [reblock(v, Z, referee_node_id=C)])
    add("forged_referee_not_announced", "counts", "a referee that announced no key",
        [reblock(v, Z, referee_node_id=Z)])
    add("forged_no_referee", "counts", "a ruling block that names no referee",
        [resealed(v, C, lambda c: block_of(c).pop("referee_node_id"))])
    add("forged_copied_block", "counts", "a reference's own record carrying a copy of a ruling block",
        [resealed(served(D, HONEST, "classify-copy"), D,
                  lambda c: c["model_attestation"]["compute_attestation"].update(adjudication=block_of(v)))])
    add("forged_many", "counts", "five forged contradictions of X count nowhere",
        [reblock(v, Z, referee_node_id=C, half_a_capsule_id=_hex(f"forged-{n}")) for n in range(5)])

    add("ack_refusal_of_a_verified_contradiction", "counts", "a refusal citing a verified contradiction of X counts",
        [v, ack_refused(v, "counted")])
    add("ack_refusal_counted_once", "counts", "two refusals of one verdict count once",
        [v, ack_refused(v, "twice-1"), ack_refused(v, "twice-2")])
    add("ack_refusal_without_the_verdict", "counts", "a refusal whose verdict was not verified here counts nowhere",
        [ack_refused(v, "alone")])
    add("ack_refusal_of_a_forged_verdict", "counts", "a refusal citing a forged verdict counts nowhere",
        [unsigned, ack_refused(v, "forged")])
    add("ack_refusal_about_the_other_twin", "counts", "a refusal of a verdict that contradicts the other twin",
        [v, ack_refused(v, "other-twin")], x=A)
    add("ack_refusal_claiming_a_contradiction", "counts",
        "the refusal's own copy of the ruling is not trusted: the verified verdict is inconclusive",
        [reblock(v, C, verdict="inconclusive", status="UNKNOWN"),
         ack_refused(v, "claimed", cited=reblock(v, C, verdict="inconclusive", status="UNKNOWN")["capsule_id"])])
    return names(cases)


# --- select: who is eligible, which tier, which node --------------------------


def ago(days: int, seconds: int = 0) -> str:
    """The time ``days`` days and ``seconds`` seconds before the corpus clock."""
    at = datetime.fromisoformat(NOW.replace("Z", "+00:00")) - timedelta(days=days, seconds=seconds)
    return at.strftime("%Y-%m-%dT%H:%M:%SZ")


def peer(node: str, *, model: str = MODEL_X, weights: str = W1, key: bool = True, blocked: bool = False) -> dict:
    return {"node_id": node, "model_hash": model, "weights_digest": weights,
            "announced_key": key_id(node) if key else None, "blocked": blocked}


def fact(node: str, bucket: str, days: int, *, model: str = MODEL_X, issued_days: int | None = None,
         seconds: int = 0) -> dict:
    out = {"node_id": node, "model_hash": model, "bucket": bucket, "recorded_at": ago(days, seconds)}
    if issued_days is not None:
        out["referee_issued_at"] = ago(issued_days)
    return out


NOBODY = {"tier": None, "pool": [], "asked": [], "not_adjudicated": "no_eligible_referee"}

#: On a case whose answer follows a default that no ruling has confirmed yet.
PROVISIONAL = "pending a ruling"


def build_select() -> tuple[list[dict], dict]:
    cases: list[dict] = []
    answers: dict = {}

    def add(name, rule, covers, peers, verdicts=(), *, expect, model=MODEL_X, weights=W1, bar_days=None, draws=None,
            provisional=False):
        """``expect`` is ``NOBODY`` or ``(tier, pool)`` or ``(tier, pool, asked)``.
        The draws default to every index of the pool, so every member is
        asked once."""
        if expect is NOBODY:
            answer, draws = NOBODY, []
        else:
            tier, pool = expect[0], expect[1]
            draws = list(range(len(pool))) if draws is None else draws
            answer = {"tier": tier, "pool": pool, "asked": expect[2] if len(expect) > 2 else pool, "not_adjudicated": None}
        cases.append({
            "name": name, "rule": rule, "covers": covers, "now": NOW, "referee_bar_days": bar_days,
            "model_hash": model, "weights_digest": weights, "twins": [A, B],
            "peers": peers, "verdicts": list(verdicts), "draws": draws,
            **({"provisional": PROVISIONAL} if provisional else {}),
        })
        answers[name] = [answer]

    twins = [peer(A), peer(B)]

    add("same_model_hash_and_digest_only", "eligibility",
        "only a node on the twins' model hash and weights digest is eligible",
        twins + [peer(C), peer(D, model=MODEL_Y), peer(E, weights=W2)], expect=(2, [C]))
    add("different_digest_never_picked", "eligibility", "the right model hash on other weights is not eligible",
        twins + [peer(C, weights=W2)], expect=NOBODY)
    add("different_model_hash_never_picked", "eligibility", "the twins' weights digest under another model hash is not eligible",
        twins + [peer(C, model=MODEL_Y)], expect=NOBODY)
    add("twin_never_picked", "eligibility", "neither twin referees its own pair", twins, expect=NOBODY)
    add("no_announced_key_never_picked", "eligibility", "a node that announced no key cannot sign a verdict",
        twins + [peer(C, key=False)], expect=NOBODY)
    add("blocked_node_never_picked", "eligibility", "a node this node stopped routing to is never asked",
        twins + [peer(C, blocked=True)], expect=NOBODY)
    add("one_eligible_among_the_rest", "eligibility", "each other node fails exactly one condition",
        twins + [peer(C, model=MODEL_Y), peer(D, weights=W2), peer(E, key=False), peer(F, blocked=True), peer(G)],
        [fact(C, "corroborated", 1), fact(D, "corroborated", 1), fact(E, "corroborated", 1), fact(F, "corroborated", 1)],
        expect=(2, [G]))

    add("tier1_before_tier2", "tiers", "a node with a corroboration for this model is asked before a node with none",
        twins + [peer(C), peer(D)], [fact(D, "corroborated", 3)], expect=(1, [D]))
    add("cold_picked_only_when_tier1_empty", "tiers", "with no corroborated node, the nodes with no history are asked",
        twins + [peer(C), peer(D)], expect=(2, [C, D]))
    add("pick_uniform_within_best_tier", "tiers", "every member of the best tier can be asked, and no other node",
        twins + [peer(C), peer(D), peer(E), peer(F)],
        [fact(C, "corroborated", 3), fact(D, "corroborated", 9), fact(E, "corroborated", 20)],
        expect=(1, [C, D, E], [E, C, C, D]), draws=[2, 0, 0, 1])
    add("ineligible_tier1_node_leaves_tier2", "tiers", "a corroborated node that is blocked does not hold the tier",
        twins + [peer(C, blocked=True), peer(D)], [fact(C, "corroborated", 3)], expect=(2, [D]))
    add("corroboration_is_per_model", "tiers", "a corroboration for another model does not lift a node's tier for this one",
        twins + [peer(C), peer(D)], [fact(C, "corroborated", 3, model=MODEL_Y)], expect=(2, [C, D]))
    add("inconclusive_is_not_a_corroboration", "tiers", "only a corroboration puts a node in the first tier",
        twins + [peer(C), peer(D)], [fact(C, "inconclusive", 3), fact(D, "not_comparable", 3)], expect=(2, [C, D]))
    add("contradiction_for_x_never_picked_for_x", "tiers", "a node contradicted on this model is not asked about it",
        twins + [peer(C), peer(D)], [fact(C, "contradicted", 5), fact(C, "corroborated", 40)],
        expect=(2, [D]))
    add("contradiction_for_x_ok_for_y", "tiers", "the same node, asked about another model it serves",
        [peer(A, model=MODEL_Y), peer(B, model=MODEL_Y), peer(C, model=MODEL_Y), peer(D, model=MODEL_Y)],
        [fact(C, "contradicted", 5), fact(C, "corroborated", 40)], model=MODEL_Y, expect=(2, [C, D]))

    add("barred_inside_d", "bar_window", "a contradiction 29 days ago bars the node for this model",
        twins + [peer(C)], [fact(C, "contradicted", 29)], expect=NOBODY)
    add("eligible_after_d", "bar_window", "a contradiction 31 days ago no longer bars it",
        twins + [peer(C)], [fact(C, "contradicted", 31)], expect=(2, [C]))
    add("corroboration_inside_d_does_not_clear", "bar_window", "a later corroboration does not end the bar early",
        twins + [peer(C)], [fact(C, "contradicted", 10), fact(C, "corroborated", 2)], expect=NOBODY)
    add("bar_on_x_leaves_y", "bar_window", "a bar on one model leaves the node eligible for another",
        [peer(A, model=MODEL_Y), peer(B, model=MODEL_Y), peer(C, model=MODEL_Y)],
        [fact(C, "contradicted", 10)], model=MODEL_Y, expect=(2, [C]))
    add("d_default_is_30", "bar_window", "with the setting unset the window is 30 days",
        twins + [peer(C)], [fact(C, "contradicted", 20)], expect=NOBODY)
    add("d_from_setting_shorter", "bar_window", "a 10-day window: a contradiction 20 days ago no longer bars",
        twins + [peer(C)], [fact(C, "contradicted", 20)], bar_days=10, expect=(2, [C]))
    add("d_from_setting_longer", "bar_window", "a 45-day window: a contradiction 40 days ago still bars",
        twins + [peer(C)], [fact(C, "contradicted", 40)], bar_days=45, expect=NOBODY)
    add("bar_runs_from_this_nodes_clock", "bar_window",
        "the window runs from when this node recorded the verdict, not from the time the referee wrote on it",
        twins + [peer(C)], [fact(C, "contradicted", 2, issued_days=60)], expect=NOBODY)
    add("other_rulings_do_not_bar", "bar_window", "only a contradiction bars a node",
        twins + [peer(C)], [fact(C, "inconclusive", 2), fact(C, "not_comparable", 2)], expect=(2, [C]))

    # Provisional: the window is half-open. A node is barred while the clock
    # is before the contradiction's time plus D, and eligible from exactly D.
    add("barred_one_second_inside_d", "bar_window", "a contradiction D days less one second ago still bars",
        twins + [peer(C)], [fact(C, "contradicted", 30, seconds=-1)], expect=NOBODY, provisional=True)
    add("eligible_at_exactly_d", "bar_window", "a contradiction exactly D days ago no longer bars",
        twins + [peer(C)], [fact(C, "contradicted", 30)], expect=(2, [C]), provisional=True)
    add("eligible_one_second_after_d", "bar_window", "a contradiction D days and one second ago no longer bars",
        twins + [peer(C)], [fact(C, "contradicted", 30, seconds=1)], expect=(2, [C]), provisional=True)
    # Provisional: a node whose bar has lapsed is eligible again with no
    # history. It is in the second tier until it has a corroboration dated
    # after the lapse; an earlier corroboration does not count.
    add("lapsed_contradiction_with_earlier_corroboration_is_tier2", "tiers",
        "a corroboration dated inside the window does not put the node back in the first tier",
        twins + [peer(C), peer(D)], [fact(C, "contradicted", 40), fact(C, "corroborated", 35)],
        expect=(2, [C, D]), provisional=True)
    add("lapsed_contradiction_with_older_corroboration_is_tier2", "tiers",
        "a corroboration from before the contradiction does not count either",
        twins + [peer(C), peer(D)], [fact(C, "corroborated", 60), fact(C, "contradicted", 40)],
        expect=(2, [C, D]), provisional=True)
    add("lapsed_contradiction_corroborated_after_the_lapse_is_tier1", "tiers",
        "the bar lapsed 10 days ago and the node was corroborated 5 days ago: first tier again",
        twins + [peer(C), peer(D)], [fact(C, "contradicted", 40), fact(C, "corroborated", 5)],
        expect=(1, [C]), provisional=True)
    return names(cases), answers


# --- request: when a referee is asked, and at most once -----------------------


def twin(node: str, text: str, *, capsule: str | None = None, temperature=0, model=MODEL_X, weights=W1) -> dict:
    return {"node_id": node, "capsule_id": capsule or _hex(f"half/{node}"), "text": text,
            "temperature": temperature, "model_hash": model, "weights_digest": weights}


def pair(half_a: dict | None = None, half_b: dict | None = None, *, bracket=BRACKET, request_digest=REQ) -> dict:
    return {"twin_bracket_id": bracket, "request_digest": request_digest,
            "halves": [half_a or twin(A, HONEST), half_b or twin(B, FLIPPED)]}


def attempt(the_pair: dict | None = None, *, selection=None, reanswer=HONEST, signs=True, manual=False) -> dict:
    """``manual``: the operator asked again, rather than the pair being seen."""
    return {"pair": the_pair or pair(), "manual": manual, "selection": selection or {"tier": 1, "asked": C},
            "referee": {"reanswer": reanswer, "signs": signs}}


def adjudicated(verdict: str, *, referee=C, tier=1) -> dict:
    return {"state": "adjudicated", "verdict": verdict, "referee": referee, "tier": tier}


def not_adjudicated(reason: str, because: str | None = None) -> dict:
    row = {"state": "not_adjudicated", "reason": reason}
    if because:
        row["because"] = because
    return row


def build_request() -> tuple[list[dict], dict]:
    cases: list[dict] = []
    answers: dict = {}

    def add(name, rule, covers, attempts, expect, *, setting=None, provisional=False):
        """``expect`` is one ``(referee calls, row, node a contradiction
        counts against)`` per attempt."""
        cases.append({"name": name, "rule": rule, "covers": covers,
                      "adjudicate_differing_twins": setting, "attempts": attempts,
                      **({"provisional": PROVISIONAL} if provisional else {})})
        answers[name] = [{"referee_calls": calls, "row": row, "counts_against": against} for calls, row, against in expect]

    contradicts_b = adjudicated(f"contradicted:{B}")

    add("differing_pair_triggers_one_call", "trigger", "twins that differ at temperature 0 on the same weights: one call",
        [attempt()], [(1, contradicts_b, B)])
    add("default_on_when_setting_unset", "trigger", "with the setting unset, a differing pair is adjudicated",
        [attempt()], [(1, contradicts_b, B)], setting=None)
    add("on_when_setting_true", "trigger", "the setting set to on", [attempt()], [(1, contradicts_b, B)], setting=True)
    add("referee_agrees_with_b", "trigger", "the re-answer is B's: the contradiction counts against A",
        [attempt(pair(twin(A, FLIPPED), twin(B, HONEST)))], [(1, adjudicated(f"contradicted:{A}"), A)])
    add("referee_from_the_second_tier", "trigger", "the row shows the tier the referee was asked from",
        [attempt(selection={"tier": 2, "asked": D})], [(1, adjudicated(f"contradicted:{B}", referee=D, tier=2), B)])
    add("referee_matches_neither", "never_contradicted", "a third answer is inconclusive and counts against nobody",
        [attempt(reanswer=OTHER)], [(1, adjudicated("inconclusive"), None)])
    add("agreeing_pair_calls_nothing", "trigger", "twins that agree: nothing runs",
        [attempt(pair(twin(A, HONEST), twin(B, HONEST)))], [(0, not_adjudicated("twins_agree"), None)])
    add("sampled_pair_calls_nothing", "trigger", "a sampled half: not comparable, nothing is asked",
        [attempt(pair(twin(A, HONEST, temperature=0.7), twin(B, FLIPPED, temperature=0.7)))],
        [(0, not_adjudicated("not_comparable", "sampled"), None)])
    add("one_sampled_half_calls_nothing", "trigger", "one sampled half is enough",
        [attempt(pair(twin(A, HONEST), twin(B, FLIPPED, temperature=0.2)))],
        [(0, not_adjudicated("not_comparable", "sampled"), None)])
    add("twins_with_different_digests_not_adjudicated", "eligibility", "twins on different weights: nothing is asked",
        [attempt(pair(twin(A, HONEST), twin(B, FLIPPED, weights=W2)))],
        [(0, not_adjudicated("not_comparable", "weights_differ"), None)])
    add("twins_with_unknown_digest_not_adjudicated", "eligibility", "a twin that names no weights: nothing is asked",
        [attempt(pair(twin(A, HONEST), twin(B, FLIPPED, weights=None)))],
        [(0, not_adjudicated("not_comparable", "weights_unknown"), None)])
    add("operator_off_calls_nothing_and_says_so", "trigger", "the operator turned adjudication off",
        [attempt()], [(0, not_adjudicated("off"), None)], setting=False)
    add("no_bracket_id_calls_nothing_and_says_so", "never_contradicted",
        "the host supplies no twin bracket id: pairs are never guessed",
        [attempt(pair(bracket=None))], [(0, not_adjudicated("host_does_not_mark_twins"), None)])

    add("second_call_same_pair_refused", "cap", "the same pair a second time makes no call",
        [attempt(), attempt()], [(1, contradicts_b, B), (0, contradicts_b, B)])
    add("resealed_halves_same_exchange_still_capped", "cap",
        "the same exchange under new record ids is the same pair",
        [attempt(), attempt(pair(twin(A, HONEST, capsule=_hex("half/resealed-a")),
                                 twin(B, FLIPPED, capsule=_hex("half/resealed-b"))))],
        [(1, contradicts_b, B), (0, contradicts_b, B)])
    add("referee_timeout_is_not_retried", "cap", "a referee that did not answer is not asked again",
        [attempt(reanswer=None), attempt()],
        [(1, not_adjudicated("referee_unreachable"), None), (0, not_adjudicated("referee_unreachable"), None)])
    add("another_referee_is_not_tried", "cap", "after one call, no second referee is asked about the pair",
        [attempt(reanswer=None), attempt(selection={"tier": 1, "asked": D})],
        [(1, not_adjudicated("referee_unreachable"), None), (0, not_adjudicated("referee_unreachable"), None)])
    add("another_bracket_is_another_pair", "cap", "the same two nodes under a new bracket id are a new pair",
        [attempt(), attempt(pair(bracket="bracket-2"))], [(1, contradicts_b, B), (1, contradicts_b, B)])
    add("another_request_is_another_pair", "cap", "the same bracket id over another request is a new pair",
        [attempt(), attempt(pair(request_digest=REQ_OTHER))], [(1, contradicts_b, B), (1, contradicts_b, B)])

    add("no_eligible_referee", "never_contradicted", "nobody eligible: not adjudicated, and nobody is contradicted",
        [attempt(selection={"not_adjudicated": "no_eligible_referee"})],
        [(0, not_adjudicated("no_eligible_referee"), None)])
    add("referee_without_plugin", "never_contradicted", "the referee re-answered but cannot sign a verdict",
        [attempt(signs=False)], [(1, not_adjudicated("referee_cannot_sign"), None)])
    add("referee_unreachable", "never_contradicted", "the referee did not answer",
        [attempt(reanswer=None)], [(1, not_adjudicated("referee_unreachable"), None)])

    # Provisional: a pair that found nobody eligible made no call, so its one
    # call is not used up. It is not looked at again on its own; the operator
    # asking again is, once somebody is eligible.
    nobody = {"not_adjudicated": "no_eligible_referee"}
    no_referee = (0, not_adjudicated("no_eligible_referee"), None)
    add("no_eligible_referee_is_not_retried_on_its_own", "cap",
        "the pair seen again, with a referee now eligible: nothing is asked and the row stays",
        [attempt(selection=nobody), attempt()], [no_referee, no_referee], provisional=True)
    add("no_eligible_referee_then_the_operator_asks_again", "cap",
        "the operator asks again once a referee is eligible: the pair's one call is made",
        [attempt(selection=nobody), attempt(manual=True)], [no_referee, (1, contradicts_b, B)], provisional=True)
    add("operator_asks_again_and_still_nobody", "cap",
        "the operator asks again with nobody eligible yet: no call, and the row stays",
        [attempt(selection=nobody), attempt(selection=nobody, manual=True)], [no_referee, no_referee], provisional=True)
    add("operator_asking_again_uses_the_one_call", "cap",
        "after the operator's re-ask made the call, the pair is never asked about again",
        [attempt(selection=nobody), attempt(manual=True), attempt(manual=True)],
        [no_referee, (1, contradicts_b, B), (0, contradicts_b, B)], provisional=True)
    return names(cases), answers


# --- counts: the counts, and the opt-in stop-routing rule --------------------


def verdict_record(kind: str, label: str, verdict: str, referee: str, days: int, *, nodes=(A, B), model=MODEL_X,
                   halves: list[str] | None = None) -> dict:
    """A record on this node's own chain. ``kind`` is ``adjudication_received``
    (a verdict delivered to it), ``adjudication_issued`` (one it signed as
    referee) or ``adjudication`` (a bare ruling block: not a verified verdict)."""
    at = "issued_at" if kind == "adjudication_issued" else "received_at"
    return {"model_attestation": {"compute_attestation": {kind: {
        "verdict": verdict,
        "verdict_capsule_id": vid(label),
        "referee_node_id": referee,
        "halves": halves or pair_of(label),
        "half_node_ids": list(nodes),
        "model_hash": model,
        at: ago(days),
    }}}}


def vid(label: str) -> str:
    return _hex(f"verdict/{label}")


def pair_of(label: str) -> list[str]:
    return [_hex(f"half/{label}-a"), _hex(f"half/{label}-b")]


def contradiction(label: str, referee: str, days: int, **kw) -> tuple[dict, dict]:
    """A received contradiction of ``node-a``, and this node's request for it."""
    record = verdict_record("adjudication_received", label, f"contradicted:{A}", referee, days, **kw)
    return record, {"referee": referee, "halves": pair_of(label)}


def step(records=(), requested=(), *, unblock=(), now=NOW) -> dict:
    return {"add_records": list(records), "add_requested": list(requested), "unblock": list(unblock), "now": now}


def counts(**by_bucket) -> dict:
    """One node's counts for one model: every bucket present, zero included."""
    return {bucket: {"count": len(by_bucket.get(bucket, [])), "verdict_capsule_ids": by_bucket.get(bucket, [])}
            for bucket in ("corroborated", "contradicted", "inconclusive", "not_comparable")}


def build_counts() -> tuple[list[dict], dict]:
    cases: list[dict] = []
    answers: dict = {}

    def add(name, rule, covers, steps, expect, *, after=None, window=None, cited=(), hook=True, blocked=()):
        """``expect`` is one ``(counts, rule, outcomes, cited)`` per step."""
        cases.append({
            "name": name, "rule": rule, "covers": covers,
            "settings": {"stop_routing_after_contradictions": after, "stop_routing_window_days": window},
            "cited": list(cited), "host": {"peer_blocks": hook, "blocked": list(blocked)}, "steps": steps,
        })
        answers[name] = [{"counts": c, "rule": r, "outcomes": o, "cited": ci} for c, r, o, ci in expect]

    def both(contradicted_ids: list[str]) -> dict:
        """The counts after contradictions of A against B: each one is a
        corroboration of B."""
        return {A: {MODEL_X: counts(contradicted=contradicted_ids)}, B: {MODEL_X: counts(corroborated=contradicted_ids)}}

    def blocked_outcome(peer_id: str, labels: list[str]) -> dict:
        return {"outcome": "blocked", "peer_id": peer_id, "verdict_capsule_ids": [vid(x) for x in labels]}

    three = [contradiction("v1", C, 0), contradiction("v2", D, 3), contradiction("v3", E, 6)]
    records3, asked3 = [r for r, _ in three], [q for _, q in three]
    ids3 = [vid("v1"), vid("v2"), vid("v3")]
    rule37 = {"after": 3, "window_days": 7}

    add("stop_rule_off_by_default", "stop_rule", "with N unset the rule is off, however many contradictions are counted",
        [step(records3, asked3)], [(both(ids3), None, [], [])])
    add("stop_rule_off_when_n_is_zero", "stop_rule", "N of 0 is off",
        [step(records3, asked3)], [(both(ids3), None, [], [])], after="0")
    add("stop_rule_off_when_n_is_not_a_number", "stop_rule", "N that is not a whole number is off, not guessed at",
        [step(records3, asked3)], [(both(ids3), None, [], [])], after="three", window="7")
    add("stop_rule_off_when_window_is_zero", "stop_rule", "a window of 0 days is off, not forever",
        [step(records3, asked3)], [(both(ids3), None, [], [])], after="3", window="0")
    add("fires_at_n_within_window", "stop_rule", "three contradictions from three referees within seven days",
        [step(records3, asked3)], [(both(ids3), rule37, [blocked_outcome(A, ["v1", "v2", "v3"])], sorted(ids3))],
        after="3", window="7")
    add("n_minus_one_does_not_fire", "stop_rule", "two contradictions and other rulings do not reach three",
        [step(records3[:2] + [
            verdict_record("adjudication_received", "v4", "inconclusive", E, 1),
            verdict_record("adjudication_received", "v5", f"contradicted:{B}", F, 1)],
            asked3[:2] + [{"referee": E, "halves": pair_of("v4")}, {"referee": F, "halves": pair_of("v5")}])],
        [({A: {MODEL_X: counts(contradicted=ids3[:2], inconclusive=[vid("v4")], corroborated=[vid("v5")])},
           B: {MODEL_X: counts(corroborated=ids3[:2], inconclusive=[vid("v4")], contradicted=[vid("v5")])}},
          rule37, [], [])], after="3", window="7")
    late = [contradiction("v1", C, 0), contradiction("v2", D, 6), contradiction("v3", E, 8)]
    add("outside_the_window_does_not_count", "stop_rule", "a contradiction eight days old is outside a seven-day window",
        [step([r for r, _ in late], [q for _, q in late])], [(both(ids3), rule37, [], [])], after="3", window="7")
    add("window_default_is_30", "stop_rule", "with the window unset it is 30 days",
        [step(*zip(contradiction("v1", C, 20)))],
        [(both([vid("v1")]), {"after": 1, "window_days": 30}, [blocked_outcome(A, ["v1"])], [vid("v1")])], after="1")

    one = [contradiction(f"r{n}", C, 0) for n in range(1, 5)]
    ids_one = [vid(f"r{n}") for n in range(1, 5)]
    extra = contradiction("r5", D, 0)
    add("one_referee_contributes_at_most_n_minus_1", "stop_rule",
        "four contradictions from one referee never reach three; a second referee's one does",
        [step([r for r, _ in one], [q for _, q in one]), step([extra[0]], [extra[1]])],
        [(both(ids_one), rule37, [], []),
         (both(ids_one + [vid("r5")]), rule37, [blocked_outcome(A, ["r1", "r2", "r5"])],
          sorted([vid("r1"), vid("r2"), vid("r5")]))],
        after="3", window="7")

    bare = [verdict_record("adjudication", f"bare{n}", f"contradicted:{A}", C, 0) for n in range(3)]
    unasked = [contradiction(f"unasked{n}", X, 0)[0] for n in range(3)]
    mine = verdict_record("adjudication_issued", "issued", f"contradicted:{A}", Q, 0)
    add("only_verified_and_asked_verdicts_count", "counts",
        "a bare ruling block and a verdict this node never asked for count nowhere; one it issued as referee counts",
        [step(bare + unasked + [mine])],
        [(both([vid("issued")]), {"after": 1, "window_days": 7}, [blocked_outcome(A, ["issued"])], [vid("issued")])],
        after="1", window="7")
    add("asked_another_referee_about_the_pair", "counts", "asking one referee does not let another's verdict count",
        [step([contradiction("v1", X, 0)[0]], [{"referee": C, "halves": pair_of("v1")}])],
        [({}, {"after": 1, "window_days": 7}, [], [])], after="1", window="7")

    same_pair = [verdict_record("adjudication_received", label, f"contradicted:{A}", C, 0, halves=pair_of("p"))
                 for label in ("p1", "p2")]
    swapped = verdict_record("adjudication_received", "p3", f"contradicted:{A}", C, 0, halves=pair_of("p")[::-1])
    add("one_count_per_referee_and_pair", "counts", "one referee counts once per pair of halves; the first recorded stands",
        [step(same_pair + [swapped], [{"referee": C, "halves": pair_of("p")}])], [(both([vid("p1")]), None, [], [])])
    add("referee_that_is_a_twin_counts_nowhere", "counts", "a verdict whose referee is one of the twins",
        [step([verdict_record("adjudication_received", "v1", f"contradicted:{B}", A, 0)],
              [{"referee": A, "halves": pair_of("v1")}])], [({}, None, [], [])])
    per_model = [contradiction("x1", C, 0), contradiction("y1", D, 0, model=MODEL_Y)]
    add("counts_are_per_model", "counts", "a node's counts are kept per model hash",
        [step([r for r, _ in per_model], [q for _, q in per_model])],
        [({A: {MODEL_X: counts(contradicted=[vid("x1")]), MODEL_Y: counts(contradicted=[vid("y1")])},
           B: {MODEL_X: counts(corroborated=[vid("x1")]), MODEL_Y: counts(corroborated=[vid("y1")])}}, None, [], [])])
    add("history_still_visible_while_barred", "bar_window",
        "a contradiction stays in the counts whatever its age: only eligibility and the rule have a window",
        [step(*zip(contradiction("old", C, 100), contradiction("recent", D, 5)))],
        [(both([vid("old"), vid("recent")]), None, [], [])])

    n2 = {"after": 2, "window_days": 7}
    first = [contradiction("u1", C, 0), contradiction("u2", D, 0)]
    third, fourth = contradiction("u3", C, 0), contradiction("u4", E, 0)
    add("undo_holds_until_new_contradictions", "stop_rule",
        "after the operator undoes the block, the same verdicts never fire again; two new ones do",
        [step([r for r, _ in first], [q for _, q in first]), step(unblock=[A]), step([third[0]], [third[1]]),
         step([fourth[0]], [fourth[1]])],
        [(both([vid("u1"), vid("u2")]), n2, [blocked_outcome(A, ["u1", "u2"])], sorted([vid("u1"), vid("u2")])),
         (both([vid("u1"), vid("u2")]), n2, [], sorted([vid("u1"), vid("u2")])),
         (both([vid("u1"), vid("u2"), vid("u3")]), n2, [], sorted([vid("u1"), vid("u2")])),
         (both([vid("u1"), vid("u2"), vid("u3"), vid("u4")]), n2, [blocked_outcome(A, ["u3", "u4"])],
          sorted([vid("u1"), vid("u2"), vid("u3"), vid("u4")]))],
        after="2", window="7")
    add("already_blocked_is_not_blocked_again", "stop_rule",
        "the rule met for a node the operator already blocked: nothing is asked, and undoing that block holds",
        [step([r for r, _ in first], [q for _, q in first]), step(unblock=[A])],
        [(both([vid("u1"), vid("u2")]), n2, [{"outcome": "already_blocked", "peer_id": A}], sorted([vid("u1"), vid("u2")])),
         (both([vid("u1"), vid("u2")]), n2, [], sorted([vid("u1"), vid("u2")]))],
        after="2", window="7", blocked=[A])
    add("verdicts_already_cited_never_count_again", "stop_rule", "a verdict an earlier block cited is spent",
        [step(records3, asked3)], [(both(ids3), rule37, [], [vid("v1")])], after="3", window="7", cited=[vid("v1")])
    add("host_without_hook_does_nothing", "stop_rule",
        "a host with no stop-routing hook: nothing is blocked and no verdict is spent",
        [step(records3, asked3)], [(both(ids3), rule37, [{"outcome": "no_host_hook"}], [])],
        after="3", window="7", hook=False)
    return names(cases), answers


# --- the files ----------------------------------------------------------------

NOTES = {
    "adjudicate": "Two halves and, when they differ, the referee's re-answer. Judged against twin_adjudicator.adjudicate.",
    "service": "Adjudicate requests to a referee node. Judged against referee_service.handle_adjudicate_request.",
    "hold": "Verdicts delivered to a node over record-push. Judged against record_push.handle_record_push.",
    "deliver": "Verdicts delivered at /evidence/deliver. Judged against adjudication_delivery.handle_delivery.",
    "classify": "Verdicts a node's references hold about it. Judged against ask_history._classify_receipts_for_x.",
    "select": "Who is eligible to referee, in which tier, and which node is asked. Answers stated from the rules.",
    "request": "When a referee is asked, and at most once per pair. Answers stated from the rules.",
    "counts": "The verdict counts and the opt-in stop-routing rule. Answers stated from the rules.",
}


def build() -> tuple[dict, dict]:
    """``(corpus documents, rule-answer documents)``, each by path."""
    select_cases, select_answers = build_select()
    request_cases, request_answers = build_request()
    counts_cases, counts_answers = build_counts()
    cases = {
        "adjudicate": build_adjudicate(),
        "service": build_service(),
        "hold": build_hold(),
        "deliver": build_deliver(),
        "classify": build_classify(),
        "select": select_cases,
        "request": request_cases,
        "counts": counts_cases,
    }
    signed = {"built_with": common.library_versions()}
    corpus = {
        path: {"v": 1, "path": path, "now": NOW, "note": NOTES[path],
               **(signed if path in common.PYTHON_PATHS else {}), "cases": cases[path]}
        for path in common.PATHS
    }
    rule_answers = {
        path: {"v": 1, "path": path, "source": "rules", "answers": answers}
        for path, answers in (("select", select_answers), ("request", request_answers), ("counts", counts_answers))
    }
    return corpus, rule_answers


def main() -> None:
    corpus, rule_answers = build()
    for path, doc in corpus.items():
        common.write_cases(path, doc)
        print(f"wrote {len(doc['cases']):3d} cases to corpus/{path}.json")
    for path, doc in rule_answers.items():
        common.write_answers(common.RULE_ANSWERS_DIR / f"{path}.json", doc)
        print(f"wrote {len(doc['answers']):3d} rule answers to rule_answers/{path}.json")


if __name__ == "__main__":
    main()
