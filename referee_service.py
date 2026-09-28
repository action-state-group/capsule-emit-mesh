# SPDX-License-Identifier: Apache-2.0
"""The referee's side of a twin adjudication: a node asked to settle two
twins that gave different answers checks what it can check itself, decides,
and signs the verdict with its own node key.

The requester that ran the twins sends, over the ``evidence-request/1``
carrier (``evidence_server.py`` routes ``subject.kind == "adjudicate"``
here)::

    {"subject": {"kind": "adjudicate"},
     "twin_bracket_id": "<the host's bracket id>"            (optional),
     "halves": [{"capsule": <provider A's signed record>,
                 "request_body": <the request it answered>,
                 "response_body": <the answer it served>}, <provider B's>],
     "referee_answer": {"request_body": <the re-answer request>,
                        "response_body": <what this node served>}}

What this node checks before it signs anything:

  1. Each half is a record its serving node signed with that node's
     announced key, and names that node as its server.
  2. Each half's answer is the body its signature covers (the record's
     ``response_digest``), and the text compared is that body's own text.
  3. Both twins answered the same request: their signed ``request_digest``
     values are equal.
  4. The referee answer is one THIS node served: a record in its own
     ledger, signed with its own key, naming it as the server, whose
     ``response_digest`` is the answer's digest. That record is cited, so a
     reader can find the referee's own record of the call.
  5. This node is neither twin.

Then the same verdict rule the requester-side referee uses
(``live_referee.referee_verdict``) decides, and the verdict record is
sealed and signed by this node. It names the referee's node id and records
how the referee's prompt is known: its answer's request is bound by this
node's own record, but the host rewrites a request before a provider seals
it, so the tie between the referee's prompt and the twins' prompt is the
requester's word (``referee_prompt: "requester_attested"``), never claimed
as checked.

The verdict is HELD beside the ledger (``issued-adjudications.jsonl``),
never written into ``capsules.jsonl``: the plugin is the one writer of this
node's chain, and it seals an ``adjudication_issued`` record citing the
verdict before the reply leaves this node (``mesh_evidence_bridge.rs``).
A repeated request for the same pair returns the verdict already issued.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent_action_capsule.verify import verify as verify_capsule
from capsule_emit.evidence_request import Refusal
from capsule_emit.signing import resolve_signer, sign_producer_envelope, verify_capsule_signature

from capsule_sidecar import digest_json
from ledger_store_backend import read_all_capsules
from live_referee import referee_verdict
from peer_keys import ENV_PEER_KEYS, announced_key_for
from twin_adjudicator import (
    NO_VERDICT_NOT_COMPARABLE,
    NO_VERDICT_REFEREE_UNREACHABLE,
    REFEREE_RECORD_RESOLVED,
    VERDICT_NOT_COMPARABLE,
    AdjudicationHalf,
    ComparisonResult,
    PreimageDigestMismatchError,
    RefereeIdentity,
    RefereeResult,
    adjudicate,
    seal_adjudication_capsule,
)

__all__ = [
    "ADJUDICATE_SUBJECT_KIND",
    "ADJUDICATION_VERDICT_MARKER",
    "ISSUED_ADJUDICATIONS_FILENAME",
    "handle_adjudicate_request",
    "is_adjudicate_request",
]

ADJUDICATE_SUBJECT_KIND = "adjudicate"
#: The member that marks a reply as an issued verdict; the plugin's
#: responder bridge seals its citing record when it sees it.
ADJUDICATION_VERDICT_MARKER = "adjudication_verdict"
ADJUDICATION_VERDICT_VERSION = 1
ISSUED_ADJUDICATIONS_FILENAME = "issued-adjudications.jsonl"

#: The referee's prompt is the requester's word (see the module doc).
REFEREE_PROMPT_REQUESTER_ATTESTED = "requester_attested"

REASON_REQUEST_MALFORMED = "request_malformed"
REASON_HALF_UNVERIFIED = "half_unverified"
REASON_TWINS_DIFFER_IN_REQUEST = "twins_differ_in_request"
REASON_REFEREE_RECORD_NOT_FOUND = "referee_record_not_found"
REASON_REFEREE_NOT_INDEPENDENT = "referee_not_independent"
REASON_REFEREE_UNNAMED = "referee_unnamed"
REASON_NO_VERDICT = "no_verdict"


class _NoRefereeAnswer(Exception):
    """The twins diverge, but no answer this node served was supplied."""


def is_adjudicate_request(request: Any) -> bool:
    return (
        isinstance(request, dict)
        and isinstance(request.get("subject"), dict)
        and request["subject"].get("kind") == ADJUDICATE_SUBJECT_KIND
    )


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _signer(state: Any):
    return resolve_signer(str(state.ledger_dir), key_path=state.signing_key_path)


def _refuse(state: Any, request_digest: str, reason: str, detail: str | None = None) -> dict[str, Any]:
    """A signed refusal, the same shape every other door answer uses."""
    issued_at = _now_iso()
    signer = _signer(state)
    stub = Refusal(request_digest=request_digest, reason=reason, issued_at=issued_at, key_id="", sig="")
    sig, key_id = signer.sign(stub.signing_body())
    refusal = Refusal(request_digest=request_digest, reason=reason, issued_at=issued_at, key_id=key_id, sig=sig)
    out = refusal.to_dict()
    if detail:
        out["detail"] = detail
    return out


def _poc(record: dict[str, Any]) -> dict[str, Any]:
    return ((record.get("model_attestation") or {}).get("compute_attestation") or {}).get("x-mesh-poc-v1") or {}


def _served_by(record: dict[str, Any]) -> str | None:
    value = (_poc(record).get("serving_provenance") or {}).get("served_by_node_id")
    return value if isinstance(value, str) and value else None


def _weights_digest(record: dict[str, Any]) -> str | None:
    model = (_poc(record).get("serving_provenance") or {}).get("model") or {}
    value = model.get("weights_digest") if isinstance(model, dict) else None
    return value if isinstance(value, str) and value else None


def _self_node_id(own_key_id: str) -> str | None:
    """This node's own id: the one announced peer whose key is this node's
    key. ``None`` when the announced keys do not name this node -- then it
    cannot say who it is, so it signs no verdict."""
    import os

    try:
        registry = json.loads(os.environ.get(ENV_PEER_KEYS) or "{}")
    except Exception:
        return None
    if not isinstance(registry, dict):
        return None
    names = [peer for peer, key in registry.items() if key == own_key_id]
    return names[0] if len(names) == 1 else None


def _signed_by_its_server(record: Any) -> str | None:
    """The node that served *record* when its announced key signed it, else
    ``None``."""
    if not isinstance(record, dict) or not record.get("capsule_id"):
        return None
    server = _served_by(record)
    if server is None:
        return None
    if not verify_capsule(record).ok or not verify_capsule_signature(record):
        return None
    if announced_key_for(server) != record.get("key_id"):
        return None
    return server


def _half(entry: Any) -> AdjudicationHalf | None:
    if not isinstance(entry, dict):
        return None
    capsule = entry.get("capsule")
    server = _signed_by_its_server(capsule)
    if server is None:
        return None
    response_body = entry.get("response_body")
    request_body = entry.get("request_body")
    if not isinstance(response_body, dict) or not isinstance(request_body, dict):
        return None
    return AdjudicationHalf(
        capsule=capsule,
        disclosed={"response_body": response_body, "request_body": request_body},
        owner_id=server,
        weights_digest=_weights_digest(capsule),
    )


def _own_referee_record(state: Any, own_key_id: str, self_id: str, response_digest: str) -> dict[str, Any] | None:
    """This node's own served record of the referee answer."""
    records, _archived = read_all_capsules(Path(state.ledger_dir))
    for record in reversed(records):
        if (
            isinstance(record, dict)
            and (record.get("effect") or {}).get("response_digest") == response_digest
            and _served_by(record) == self_id
            and record.get("key_id") == own_key_id
            and verify_capsule(record).ok
            and verify_capsule_signature(record)
        ):
            return record
    return None


def _issued_path(state: Any) -> Path:
    return Path(state.ledger_dir) / ISSUED_ADJUDICATIONS_FILENAME


def _already_issued(state: Any, halves: list[str]) -> dict[str, Any] | None:
    path = _issued_path(state)
    if not path.is_file():
        return None
    for line in path.read_text().splitlines():
        try:
            held = json.loads(line)
        except Exception:
            continue
        if isinstance(held, dict) and sorted(held.get("halves") or []) == sorted(halves):
            return held
    return None


def _hold(state: Any, held: dict[str, Any]) -> None:
    path = _issued_path(state)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(held) + "\n")


def _reply(held: dict[str, Any]) -> dict[str, Any]:
    return {ADJUDICATION_VERDICT_MARKER: ADJUDICATION_VERDICT_VERSION, **held}


def handle_adjudicate_request(state: Any, request_bytes: bytes) -> dict[str, Any]:
    """Answer one adjudicate request with a signed verdict or a signed
    refusal; never raises on bad input."""
    request_digest = hashlib.sha256(request_bytes).hexdigest()
    try:
        request = json.loads(request_bytes)
    except Exception:
        return _refuse(state, request_digest, REASON_REQUEST_MALFORMED)
    if not is_adjudicate_request(request):
        return _refuse(state, request_digest, REASON_REQUEST_MALFORMED)
    entries = request.get("halves")
    answer = request.get("referee_answer")
    bracket = request.get("twin_bracket_id")
    if (
        not isinstance(entries, list)
        or len(entries) != 2
        or (answer is not None and not (isinstance(answer, dict) and isinstance(answer.get("response_body"), dict)))
        or (bracket is not None and not isinstance(bracket, str))
    ):
        return _refuse(state, request_digest, REASON_REQUEST_MALFORMED)

    signer = _signer(state)
    self_id = _self_node_id(signer.key_id)
    if self_id is None:
        return _refuse(state, request_digest, REASON_REFEREE_UNNAMED)

    half_a, half_b = _half(entries[0]), _half(entries[1])
    if half_a is None or half_b is None:
        return _refuse(state, request_digest, REASON_HALF_UNVERIFIED)
    if self_id in (half_a.owner_id, half_b.owner_id):
        return _refuse(state, request_digest, REASON_REFEREE_NOT_INDEPENDENT)
    request_a = (half_a.capsule.get("effect") or {}).get("request_digest")
    request_b = (half_b.capsule.get("effect") or {}).get("request_digest")
    if not request_a or request_a != request_b:
        return _refuse(state, request_digest, REASON_TWINS_DIFFER_IN_REQUEST)

    halves = [half_a.capsule_id, half_b.capsule_id]
    held = _already_issued(state, halves)
    if held is not None:
        return _reply(held)

    # The referee answer decides only when the twins diverge; it must then be
    # one this node served (found in its own ledger).
    answer_body = answer["response_body"] if answer is not None else None
    record = (
        _own_referee_record(state, signer.key_id, self_id, digest_json(answer_body))
        if answer_body is not None
        else None
    )
    referee_text = (
        ((answer_body.get("choices") or [{}])[0].get("message") or {}).get("content") or ""
        if answer_body is not None
        else ""
    )

    def _referee(a: AdjudicationHalf, b: AdjudicationHalf, comparison: ComparisonResult) -> RefereeResult:
        if record is None:
            raise _NoRefereeAnswer()
        return RefereeResult(
            verdict=referee_verdict(a, b, comparison, referee_text),
            logprobs_absent=True,
            capsule_id=record["capsule_id"],
            referee_record_status=REFEREE_RECORD_RESOLVED,
            identity=RefereeIdentity(referee_id=self_id, referee_capsule_id=record["capsule_id"]),
        )

    try:
        outcome = adjudicate(half_a, half_b, referee=_referee, referee_owner_id=self_id)
    except PreimageDigestMismatchError as exc:
        return _refuse(state, request_digest, REASON_HALF_UNVERIFIED, detail=str(exc))
    if outcome.no_verdict_reason == NO_VERDICT_NOT_COMPARABLE:
        # A signed ruling that the twins cannot be compared -- never a
        # corroboration or a contradiction.
        outcome = dataclasses.replace(outcome, verdict=VERDICT_NOT_COMPARABLE, no_verdict_reason=None)
    elif outcome.verdict is None:
        if outcome.no_verdict_reason == NO_VERDICT_REFEREE_UNREACHABLE and record is None:
            return _refuse(state, request_digest, REASON_REFEREE_RECORD_NOT_FOUND)
        return _refuse(state, request_digest, REASON_NO_VERDICT, detail=outcome.no_verdict_reason)

    extra: dict[str, Any] = {
        "referee_node_id": self_id,
        "half_a_node_id": half_a.owner_id,
        "half_b_node_id": half_b.owner_id,
        "twins_request_digest": request_a,
        "referee_prompt": REFEREE_PROMPT_REQUESTER_ATTESTED,
    }
    if outcome.referee_called and answer_body is not None:
        extra["referee_answer_digest"] = digest_json(answer_body)
    if bracket:
        extra["twin_bracket_id"] = bracket
    capsule = seal_adjudication_capsule(outcome, extra=extra)
    if capsule is None:
        return _refuse(state, request_digest, REASON_NO_VERDICT)
    capsule["signature"], capsule["key_id"] = sign_producer_envelope(signer, capsule["capsule_id"])

    held = {
        "verdict": outcome.verdict,
        "verdict_capsule_id": capsule["capsule_id"],
        "verdict_capsule": capsule,
        "referee_node_id": self_id,
        # Cited only when the referee's answer decided (the twins differed).
        "referee_capsule_id": record["capsule_id"] if outcome.referee_called and record else None,
        "halves": halves,
        "half_node_ids": [half_a.owner_id, half_b.owner_id],
        "twin_bracket_id": bracket,
        "issued_at": _now_iso(),
    }
    _hold(state, held)
    return _reply(held)
