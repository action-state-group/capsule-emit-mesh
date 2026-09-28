# SPDX-License-Identifier: Apache-2.0
"""The requester's side of a twin adjudication: it sends the twins to an
independent referee and delivers the verdict the referee signed. It never
seals a verdict of its own.

1. Compare the two answers. When they diverge (and neither half was
   sampled), ask the referee to re-answer the original request
   (``live_referee.call_referee``, over the mesh's ``x-mesh-target``).
2. Send the referee an adjudicate request over the ``evidence-request/1``
   carrier (this node's ``mesh_evidence_request`` tool). The referee's door
   checks what it can check itself and answers with a verdict it signed, or
   a signed refusal (``referee_service.py``).
3. Deliver the signed verdict to both judged providers and to this node
   (this node's ``deliver_adjudication`` tool). Each receiver's door checks
   the referee's signature and holds the verdict, and its plugin seals
   ``adjudication_received``; a signed refusal is sealed on this node as
   ``adjudication_ack_refused``.
"""
from __future__ import annotations

import json
import urllib.request
from collections.abc import Callable
from typing import Any

from live_referee import call_referee
from twin_adjudicator import AdjudicationHalf, compare_transcripts, half_was_sampled

__all__ = [
    "ADJUDICATION_VERDICT_MARKER",
    "adjudicate_request",
    "deliver_verdict",
    "request_verdict",
]

ADJUDICATION_VERDICT_MARKER = "adjudication_verdict"

#: ``(peer_id, request map) -> the peer's answer``.
Post = Callable[[str, dict[str, Any]], dict[str, Any]]


def _tool(local_host_api: str, plugin_name: str, tool: str, args: dict[str, Any], timeout: float) -> dict[str, Any]:
    url = f"{local_host_api.rstrip('/')}/api/plugins/{plugin_name}/tools/{tool}"
    req = urllib.request.Request(
        url, data=json.dumps(args).encode("utf-8"), headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def adjudicate_request(
    half_a: AdjudicationHalf,
    half_b: AdjudicationHalf,
    *,
    referee_answer: tuple[dict[str, Any], dict[str, Any]] | None,
    twin_bracket_id: str | None = None,
) -> dict[str, Any]:
    """The adjudicate request map (``referee_service.py``'s wire)."""
    request: dict[str, Any] = {
        "subject": {"kind": "adjudicate"},
        "halves": [
            {"capsule": h.capsule, "request_body": h.request_body, "response_body": h.response_body}
            for h in (half_a, half_b)
        ],
    }
    if twin_bracket_id:
        request["twin_bracket_id"] = twin_bracket_id
    if referee_answer is not None:
        request["referee_answer"] = {"request_body": referee_answer[0], "response_body": referee_answer[1]}
    return request


def request_verdict(
    half_a: AdjudicationHalf,
    half_b: AdjudicationHalf,
    *,
    referee_peer_id: str,
    local_api_base_url: str,
    local_host_api: str,
    plugin_name: str,
    model: str,
    nonce: str,
    twin_bracket_id: str | None = None,
    seed: int | None = None,
    timeout: float = 60.0,
    post: Post | None = None,
) -> dict[str, Any]:
    """Ask *referee_peer_id* for a signed verdict on the two halves. Returns
    the referee's answer unchanged: an issued verdict (it carries
    :data:`ADJUDICATION_VERDICT_MARKER` and ``verdict_capsule``) or a signed
    refusal (``reason``)."""
    comparison = compare_transcripts(half_a.response_text, half_b.response_text)
    answer = None
    if comparison.divergence_index is not None and not (half_was_sampled(half_a) or half_was_sampled(half_b)):
        request_bytes, response_body = call_referee(
            half_a,
            comparison,
            local_api_base_url=local_api_base_url,
            target_peer_id=referee_peer_id,
            model=model,
            seed=seed,
            nonce=nonce,
            timeout=timeout,
        )
        answer = (json.loads(request_bytes), response_body)
    request = adjudicate_request(half_a, half_b, referee_answer=answer, twin_bracket_id=twin_bracket_id)
    if post is None:

        def post(peer: str, req: dict[str, Any]) -> dict[str, Any]:
            return _tool(local_host_api, plugin_name, "mesh_evidence_request", {"peer_id": peer, "request": req}, timeout)

    return post(referee_peer_id, request)


def deliver_verdict(
    verdict_capsule: dict[str, Any],
    peer_ids: list[str],
    *,
    local_host_api: str,
    plugin_name: str,
    timeout: float = 60.0,
) -> dict[str, dict[str, Any]]:
    """Deliver a referee-signed verdict to each of *peer_ids* (this node's
    own id delivers to itself). Returns each receiver's answer."""
    replies: dict[str, dict[str, Any]] = {}
    for peer in peer_ids:
        try:
            replies[peer] = _tool(
                local_host_api,
                plugin_name,
                "deliver_adjudication",
                {"peer_id": peer, "verdict_capsule": verdict_capsule},
                timeout,
            )
        except Exception as exc:  # noqa: BLE001 -- reported per receiver, never raised for one
            replies[peer] = {"error": str(exc)[:300]}
    return replies
