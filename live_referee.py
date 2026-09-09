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
  `POST {local_api_base_url}/v1/chat/completions`, headers
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
  [mesh-referee-capsule-citation] `capsule_sidecar.CLIENT_NONCE_HEADER`
  (`X-Capsule-Client-Nonce`) carries `nonce` -- the referee node's own
  sidecar reads it exactly like any other served request's client nonce
  (`capsule_sidecar._resolve_client_nonce`) and seals it as `client_nonce`
  on its OWN capsule, which is what makes it findable afterwards via
  `correlation{by: "nonce", value: nonce}` at that node's evidence door.

What this is not
-----------------
  - NOT a selector. Which peer to ask is `twin_selection.select_referee`'s
    job entirely; this module takes `target_peer_id` as given.
  - NOT a sealer. The referee node's OWN sidecar seals an ordinary capsule
    for every request it serves, the same as any other served request in
    this repo. LIVE-CONFIRMED 2026-09-08: the current live plugin binary
    never returns an `X-Capsule-Id` response header (only
    `x-mesh-served-by`) -- the capsule id is only ever visible in the
    SERVING node's own local ledger, which the requester has no direct
    wire access to. [mesh-referee-capsule-citation] So this module instead
    sends the referee call with its own request nonce
    (`capsule_sidecar.CLIENT_NONCE_HEADER`) and, after the call, resolves
    the referee's sealed half via that node's OWN evidence door --
    `correlation{by: "nonce", value: <the nonce this module sent}` (E15
    HTTP `POST /evidence-request`, or the plugin mesh stream for a peer
    with no reachable HTTP door -- see `resolve_referee_record`) -- and
    verifies whatever comes back OFFLINE, never trusting the door's say-so
    alone: the resolved record's own declared response digest must match
    what this module actually received from the referee HTTP call before
    `RefereeResult.capsule_id` is ever populated. `REFEREE_RECORD_RESOLVED`
    / `REFEREE_RECORD_CITATION_UNVERIFIED` / `REFEREE_RECORD_UNRESOLVED`
    (`twin_adjudicator`'s three states) name which of those happened; an
    unreachable/unconfigured door is cited BY NONCE ONLY
    (`referee_record_status=REFEREE_RECORD_UNRESOLVED`), never silently
    dropped. This module never seals or re-signs anything of its own
    regardless.
  - NOT a source of the referee's owner identity. `adjudicate()`'s
    independence refusal needs `referee_owner_id` supplied BEFORE this
    module is even called (from the `PeerInfo` `select_referee` already
    picked) -- this module has no way to know the referee's owner ahead of
    asking it, and does not try to derive one from the response.
"""
from __future__ import annotations

import functools
import json
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from capsule_emit.bundle import Bundle, verify_bundle

from ask_history import post_evidence_request, post_mesh_evidence_request
from capsule_sidecar import CLIENT_NONCE_HEADER, digest_json
from twin_adjudicator import (
    REFEREE_RECORD_CITATION_UNVERIFIED,
    REFEREE_RECORD_RESOLVED,
    REFEREE_RECORD_UNRESOLVED,
    VERDICT_INCONCLUSIVE,
    AdjudicationHalf,
    ComparisonResult,
    Referee,
    RefereeIdentity,
    RefereeResult,
    contradicted,
    token_at,
    top2_logprob_margin,
)
from twin_selection import PeerInfo

__all__ = [
    "MESH_TARGET_HEADER",
    "RefereeCallError",
    "RefereeRecordResolution",
    "build_live_referee",
    "live_referee",
    "peer_info_from_status",
    "resolve_referee_record",
]

#: mesh-llm's routing header (`ingress.rs::parse_mesh_target_header`) -- one
#: value, the FULL 64-hex-char EndpointId, never the truncated display id.
MESH_TARGET_HEADER = "x-mesh-target"


class RefereeCallError(RuntimeError):
    """The live HTTP call to the selected referee node itself failed --
    network error, non-2xx, or an unparseable response body. Distinct from
    a referee DISAGREEING (a normal `RefereeResult`, never an exception) --
    this is the call never producing an answer at all."""


@dataclass(frozen=True)
class RefereeRecordResolution:
    """What `resolve_referee_record` found when it went looking for the
    referee's own sealed half. `status` is always one of
    `twin_adjudicator`'s three closed states (`REFEREE_RECORD_RESOLVED` /
    `REFEREE_RECORD_CITATION_UNVERIFIED` / `REFEREE_RECORD_UNRESOLVED`) --
    `capsule_id` is set ONLY on `REFEREE_RECORD_RESOLVED`, never on the
    other two (an unverified or unresolved record is never cited as if it
    were trustworthy)."""

    status: str
    nonce: str
    capsule_id: str | None = None


def _referee_nonce_correlation_request(nonce: str) -> dict[str, Any]:
    """The E15 request map for `correlation{by: "nonce", value: nonce}` --
    same shape `ask_history.py`'s own (private) `_build_request_map` emits
    for a correlation subject; built directly here rather than reaching
    into that module's private helper (same precedent `ask_history.py`
    itself cites for not reaching into `capsule_emit.evidence_request`'s
    own private `_iter_values_by_key`)."""
    return {"subject": {"kind": "correlation", "by": "nonce", "value": nonce}, "coverage": {}}


def resolve_referee_record(
    nonce: str,
    *,
    expected_response_digest: str,
    post: Callable[[dict[str, Any]], dict[str, Any]] | None,
) -> RefereeRecordResolution:
    """Resolve the referee node's OWN sealed half for *nonce* via its
    evidence door and verify it OFFLINE before ever trusting it.

    *post* is an already-bound transport -- `functools.partial(
    post_evidence_request, evidence_door_base_url)` for E15 HTTP, or
    `functools.partial(post_mesh_evidence_request, local_host_api,
    local_plugin_name, referee_peer_id)` for the plugin mesh stream (same
    injectable-callable shape `ask_history.fetch_all_pages(post, ...)`
    already uses) -- or `None` when no evidence-door transport is
    configured at all.

    *expected_response_digest* is the digest THIS module itself computed
    from the referee HTTP call's own response body (`digest_json`, the
    same digest domain `capsule_sidecar` seals into `effect.response_digest`
    -- see `capsule_sidecar.py`'s `response_digest = digest_json(response_json)`).
    A resolved record's declared digest must match it exactly, or the
    record is refused as unverified -- this is what stops a door that
    (bug, or an adversary) hands back an unrelated capsule for a reused or
    guessed nonce from ever being cited as the referee's own.

    Three states, never a silent fourth (`RefereeRecordResolution.status`):
      - `REFEREE_RECORD_RESOLVED` -- a bundle verified offline
        (`capsule_emit.bundle.verify_bundle`) AND its own declared
        `effect.response_digest` matched. `capsule_id` is that bundle's
        own capsule id (content-addressed -- "the capsule digest").
      - `REFEREE_RECORD_CITATION_UNVERIFIED` -- the door answered with at
        least one bundle for this nonce, but none both verified AND
        matched. Never cited.
      - `REFEREE_RECORD_UNRESOLVED` -- `post is None`, the door was
        unreachable, or it refused / had nothing for this nonce. Cited by
        nonce alone by the caller -- never silently dropped.

    Never raises: a transport failure degrades to `REFEREE_RECORD_UNRESOLVED`,
    the same "a reference that won't talk is itself an honest, countable
    outcome" discipline `ask_history.run_references` uses.
    """
    if post is None:
        return RefereeRecordResolution(status=REFEREE_RECORD_UNRESOLVED, nonce=nonce)

    try:
        payload = post(_referee_nonce_correlation_request(nonce))
    except urllib.error.URLError:
        return RefereeRecordResolution(status=REFEREE_RECORD_UNRESOLVED, nonce=nonce)

    if "reason" in payload:
        return RefereeRecordResolution(status=REFEREE_RECORD_UNRESOLVED, nonce=nonce)

    bundles = payload.get("bundles") or []
    for bd in bundles:
        bundle = Bundle.from_dict(bd)
        ok, _errors = verify_bundle(bundle)
        if not ok:
            continue
        declared = (bundle.receipt.get("effect") or {}).get("response_digest")
        if declared == expected_response_digest:
            return RefereeRecordResolution(
                status=REFEREE_RECORD_RESOLVED, nonce=nonce, capsule_id=bundle.receipt.get("capsule_id")
            )

    if bundles:
        # The door answered for this nonce, but nothing both verified and
        # matched -- refuse to cite, distinct from never having answered.
        return RefereeRecordResolution(status=REFEREE_RECORD_CITATION_UNVERIFIED, nonce=nonce)
    return RefereeRecordResolution(status=REFEREE_RECORD_UNRESOLVED, nonce=nonce)


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
    nonce: str,
    timeout: float = 30.0,
    evidence_door_base_url: str | None = None,
    evidence_via: str = "http",
    local_host_api: str = "http://127.0.0.1:8080",
    local_plugin_name: str = "admission-policy",
) -> RefereeResult:
    """The live E17c third-node recompute -- see module docstring for the
    wire shape and the verdict rule. Raises `RefereeCallError` on a network
    or transport failure; never raises for a referee that simply answers
    with a token matching neither twin (that is `inconclusive`, a normal
    result).

    [mesh-referee-capsule-citation] *nonce* rides `capsule_sidecar.
    CLIENT_NONCE_HEADER` on the outbound call, then, after the referee
    answers, is used to resolve and verify the referee's own sealed half
    via `resolve_referee_record` -- `evidence_door_base_url` (E15 HTTP) or
    `evidence_via="mesh"` (the plugin mesh stream, reached through
    `local_host_api`/`local_plugin_name`, same transport shape
    `ask_history.py --via mesh` uses) name where to ask. Neither given ->
    `resolve_referee_record` is called with `post=None`, which resolves to
    `REFEREE_RECORD_UNRESOLVED` honestly rather than skipping the citation
    -- `RefereeResult.referee_record_nonce` is always set to *nonce* so the
    caller can still cite it even then.
    """
    if comparison.divergence_index is None:
        raise ValueError("live_referee() requires an actual divergence -- comparison.divergence_index is None")

    body = _referee_request_body(half_a, comparison, model=model, seed=seed)
    req = urllib.request.Request(
        url=f"{local_api_base_url.rstrip('/')}/v1/chat/completions",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            MESH_TARGET_HEADER: target_peer_id,
            CLIENT_NONCE_HEADER: nonce,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            response_bytes = resp.read()
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

    if evidence_via == "mesh":
        post = functools.partial(post_mesh_evidence_request, local_host_api, local_plugin_name, target_peer_id)
    elif evidence_door_base_url:
        post = functools.partial(post_evidence_request, evidence_door_base_url)
    else:
        post = None
    record = resolve_referee_record(nonce, expected_response_digest=digest_json(response_body), post=post)

    return RefereeResult(
        verdict=verdict,
        margin=margin if margin is not None else 0.0,
        logprobs_absent=margin is None,
        capsule_id=record.capsule_id,
        referee_record_status=record.status,
        referee_record_nonce=nonce,
        # [mesh-referee-attribution] The referee's stable identity is its
        # target_peer_id -- the same mesh peer id the caller used to reach
        # it.  `referee_capsule_id` is forwarded from the resolved record
        # (None when unresolved) so the adjudication capsule can cite it.
        identity=RefereeIdentity(
            referee_id=target_peer_id,
            referee_capsule_id=record.capsule_id,
        ),
    )


def build_live_referee(
    *,
    local_api_base_url: str,
    target_peer_id: str,
    model: str,
    seed: int,
    nonce: str,
    timeout: float = 30.0,
    evidence_door_base_url: str | None = None,
    evidence_via: str = "http",
    local_host_api: str = "http://127.0.0.1:8080",
    local_plugin_name: str = "admission-policy",
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
            nonce=nonce,
            timeout=timeout,
            evidence_door_base_url=evidence_door_base_url,
            evidence_via=evidence_via,
            local_host_api=local_host_api,
            local_plugin_name=local_plugin_name,
        )

    return _referee
