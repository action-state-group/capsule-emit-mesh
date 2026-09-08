# SPDX-License-Identifier: Apache-2.0
"""[mesh-referee-live-e17c] -- the live third-node referee call (E17c).

The piece `twin_adjudicator.py` and `twin_selection.py` were both built and
tested for but never dialed themselves ("NOT a network call" -- see both
modules' docstrings): given a text divergence between two twins,

  1. `twin_selection.select_referee` picks a live peer independent of BOTH
     twins (same weights, hard-excluded on shared owner, tie-band random).
  2. THIS module sends the twins' agreed-upon response PREFIX to that peer
     over the mesh's own `x-mesh-target` routing header, asking for exactly
     one more (greedy, seeded) token.
  3. The referee's one token is compared against each twin's own token at
     `comparison.divergence_index` to decide `corroborated` /
     `contradicted:<owner_id>` / `inconclusive` -- the same closed
     vocabulary `twin_adjudicator.contradicted()` builds.
  4. The result feeds straight into `twin_adjudicator.adjudicate(...,
     referee=...)`, which independently re-checks the referee isn't
     same-owner as either twin BEFORE ever calling it (defense in depth --
     `select_referee`'s hard exclusion should already guarantee this; this
     module never assumes a caller wired that check correctly upstream).

Wire shape (verify-don't-build -- see the 2026-09-08 ruling's item 3):
  `POST {local_api_base_url}/v1/chat/completions`, header
  `x-mesh-target: <target peer's FULL EndpointId hex>` (mesh-llm's
  `parse_mesh_target_header` requires the full 64-hex-char id -- the
  truncated ~10-char id `/api/status` `peers[]` shows for humans is NOT
  accepted -- LIVE-CONFIRMED 2026-09-08 against M4, self-targeted: the
  header is honored, `x-mesh-served-by` echoes it back, and `max_tokens`/
  `temperature`/`seed` all reach the serving path unchanged -- see
  `ADJUDICATION-AND-BUNDLE-TEST.md` Task 3). Body reconstructs [original
  request messages] + one trailing `{"role": "assistant", "content":
  <agreed prefix>}` message, so the referee node continues (prefills) the
  assistant turn rather than answering it fresh -- this is an ASSUMPTION
  about how the `skippy` backend treats a trailing assistant message, not
  something this repo has independently confirmed against a live node;
  treat it as unverified until a live run's transcript shows the referee's
  continuation actually lines up token-for-token with the twins' own
  prefix. `temperature: 0, max_tokens: 1, seed: <caller-supplied>` --
  deliberately NEVER `logprobs`/`top_logprobs`: LIVE-CONFIRMED 2026-09-08
  that the current runtime 400s the ENTIRE request when `logprobs: true`
  is set (`unsupported_model_feature` -- the same finding
  `ADJUDICATION-AND-BUNDLE-TEST.md` Task 1 made for the twins' own
  requests), so asking for logprobs here would break the referee call
  outright, not just come back absent. `top2_logprob_margin` therefore
  reads `None` (absent) on every live call today -- `RefereeResult.
  logprobs_absent` is expected to be `True` in practice until a runtime
  actually supports the feature; this is the "inert" case the module
  docstring and 2026-09-08 ruling name explicitly.

What this is not
-----------------
  - NOT a selector. Which peer to ask is `twin_selection.select_referee`'s
    job entirely; this module takes `target_peer_id` as given.
  - NOT a sealer. The referee node's OWN sidecar seals an ordinary capsule
    for every request it serves, the same as any other served request in
    this repo. This module ATTEMPTS to read an `X-Capsule-Id` response
    header back so the caller can cite it, but LIVE-CONFIRMED 2026-09-08:
    the current live plugin binary does not return that header at all
    (only `x-mesh-served-by`) -- `RefereeResult.capsule_id` is `None` in
    practice against today's runtime, a real, open gap (see
    `ADJUDICATION-AND-BUNDLE-TEST.md` Task 3), not something this module
    can work around client-side: the capsule id is only ever visible in the
    SERVING node's own local ledger, which the requester has no wire
    access to today. This module never seals or re-signs anything of its
    own regardless.
  - NOT a source of the referee's owner identity. `adjudicate()`'s
    independence refusal needs `referee_owner_id` supplied BEFORE this
    module is even called (from the `PeerInfo` `select_referee` already
    picked) -- this module has no way to know the referee's owner ahead of
    asking it, and does not try to derive one from the response.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from twin_adjudicator import (
    VERDICT_INCONCLUSIVE,
    AdjudicationHalf,
    ComparisonResult,
    Referee,
    RefereeResult,
    contradicted,
    token_at,
    top2_logprob_margin,
)
from twin_selection import PeerInfo

__all__ = [
    "MESH_TARGET_HEADER",
    "RefereeCallError",
    "build_live_referee",
    "live_referee",
    "peer_info_from_status",
]

#: mesh-llm's routing header (`ingress.rs::parse_mesh_target_header`) -- one
#: value, the FULL 64-hex-char EndpointId, never the truncated display id.
MESH_TARGET_HEADER = "x-mesh-target"


class RefereeCallError(RuntimeError):
    """The live HTTP call to the selected referee node itself failed --
    network error, non-2xx, or an unparseable response body. Distinct from
    a referee DISAGREEING (a normal `RefereeResult`, never an exception) --
    this is the call never producing an answer at all."""


def peer_info_from_status(peer_json: dict[str, Any], *, weights_digest: str | None = None) -> PeerInfo:
    """Adapt one entry of live `/api/status` `peers[]` JSON into a
    `twin_selection.PeerInfo`.

    `weights_digest` is deliberately NOT read off `peer_json` -- its
    `models`/`hosted_models` entries are the per-node
    `local-gguf/sha256-...` LOAD id, explicitly NOT the cross-node-stable
    weights_digest E5 would provide (see `twin_adjudicator.py`'s
    docstring: "stubbed until E5 lands"). A caller must supply it
    explicitly; the honest default is `None` -- never fabricated from a
    field that isn't actually stable across nodes.

    Never raises on a peer missing optional fields -- every `PeerInfo`
    field but `peer_id` already defaults to "not disclosed"
    (`twin_selection.PeerInfo`'s own discipline); this adapter just carries
    that through.
    """
    owner = peer_json.get("owner") or {}
    gpus = peer_json.get("gpus") or []
    gpu_names = tuple(g.get("name") for g in gpus if isinstance(g, dict) and g.get("name")) or None
    return PeerInfo(
        peer_id=peer_json["id"],
        state=peer_json.get("state") or "serving",
        weights_digest=weights_digest,
        rtt_ms=peer_json.get("rtt_ms"),
        latency_source=peer_json.get("latency_source"),
        owner_id=owner.get("owner_id") if isinstance(owner, dict) else None,
        owner_verified=bool(owner.get("verified")) if isinstance(owner, dict) else False,
        hostname=peer_json.get("hostname"),
        gpus=gpu_names,
        is_soc=peer_json.get("is_soc"),
        first_joined_mesh_ts=peer_json.get("first_joined_mesh_ts"),
    )


def _referee_request_body(half_a: AdjudicationHalf, comparison: ComparisonResult, *, model: str, seed: int) -> bytes:
    prefix_tokens = half_a.response_text.split()[: comparison.divergence_index]
    prefix_text = " ".join(prefix_tokens)

    original_messages = list(half_a.request_body.get("messages") or [])
    if original_messages:
        messages = [*original_messages, {"role": "assistant", "content": prefix_text}]
    else:
        # No disclosed request preimage -- best-effort fallback, honestly a
        # weaker recompute than a real prefill (see module docstring).
        messages = [{"role": "user", "content": prefix_text}]

    return json.dumps(
        {
            "model": model,
            "messages": messages,
            "temperature": 0,
            "max_tokens": 1,
            "seed": seed,
            # Deliberately NO logprobs/top_logprobs -- LIVE-CONFIRMED
            # 2026-09-08 that the current runtime 400s the whole request
            # when asked for them (see module docstring). top2_logprob_margin
            # reads None (absent) from a plain response, which is the
            # correct, honest outcome today.
        }
    ).encode("utf-8")


def live_referee(
    half_a: AdjudicationHalf,
    half_b: AdjudicationHalf,
    comparison: ComparisonResult,
    *,
    local_api_base_url: str,
    target_peer_id: str,
    model: str,
    seed: int,
    timeout: float = 30.0,
) -> RefereeResult:
    """The live E17c third-node recompute -- see module docstring for the
    wire shape and the verdict rule. Raises `RefereeCallError` on a network
    or transport failure; never raises for a referee that simply answers
    with a token matching neither twin (that is `inconclusive`, a normal
    result).
    """
    if comparison.divergence_index is None:
        raise ValueError("live_referee() requires an actual divergence -- comparison.divergence_index is None")

    body = _referee_request_body(half_a, comparison, model=model, seed=seed)
    req = urllib.request.Request(
        url=f"{local_api_base_url.rstrip('/')}/v1/chat/completions",
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", MESH_TARGET_HEADER: target_peer_id},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            response_bytes = resp.read()
            capsule_id = resp.headers.get("X-Capsule-Id")
    except urllib.error.HTTPError as exc:
        detail = exc.read()[:500]
        raise RefereeCallError(f"referee call to {target_peer_id!r} failed: HTTP {exc.code}: {detail!r}") from exc
    except urllib.error.URLError as exc:
        raise RefereeCallError(f"referee call to {target_peer_id!r} failed: {exc.reason}") from exc

    try:
        response_body = json.loads(response_bytes)
    except json.JSONDecodeError as exc:
        raise RefereeCallError(f"referee response was not valid JSON: {response_bytes[:200]!r}") from exc

    referee_text = ((response_body.get("choices") or [{}])[0].get("message") or {}).get("content") or ""
    referee_token = token_at(referee_text, 0)

    token_a = token_at(half_a.response_text, comparison.divergence_index)
    token_b = token_at(half_b.response_text, comparison.divergence_index)
    matches_a = referee_token is not None and referee_token == token_a
    matches_b = referee_token is not None and referee_token == token_b

    if matches_a and not matches_b and half_b.owner_id:
        verdict = contradicted(half_b.owner_id)
    elif matches_b and not matches_a and half_a.owner_id:
        verdict = contradicted(half_a.owner_id)
    else:
        # Matches neither twin, matches both (impossible given a genuine
        # divergence, but never trusted blindly), or the contradicted
        # party's owner_id is unknown (never fabricate a verdict citing an
        # owner we can't name) -- all fall through to inconclusive.
        verdict = VERDICT_INCONCLUSIVE

    margin = top2_logprob_margin(response_body, 0)

    return RefereeResult(
        verdict=verdict,
        margin=margin if margin is not None else 0.0,
        logprobs_absent=margin is None,
        capsule_id=capsule_id,
    )


def build_live_referee(
    *,
    local_api_base_url: str,
    target_peer_id: str,
    model: str,
    seed: int,
    timeout: float = 30.0,
) -> Referee:
    """Bind the live-call parameters into a `twin_adjudicator.Referee`
    callable -- `adjudicate(half_a, half_b, referee=build_live_referee(...))`
    is the whole live E17c wiring from the caller's side."""

    def _referee(half_a: AdjudicationHalf, half_b: AdjudicationHalf, comparison: ComparisonResult) -> RefereeResult:
        return live_referee(
            half_a,
            half_b,
            comparison,
            local_api_base_url=local_api_base_url,
            target_peer_id=target_peer_id,
            model=model,
            seed=seed,
            timeout=timeout,
        )

    return _referee
