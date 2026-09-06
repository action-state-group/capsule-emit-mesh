#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""``ask_history.py`` -- the requester side of E15's HTTP evidence door.

Posts an E14 request map to a peer's ``POST /evidence-request``
(``evidence_server.py``), then verifies whatever comes back OFFLINE, from
the response bytes alone -- no further trust in the peer, no second round
trip:

  * an Artifact -> reconstruct each ``capsule_emit.bundle.Bundle`` from its
    own ``.to_dict()`` shape (``Bundle.from_dict``) and run
    ``capsule_emit.bundle.verify_bundle()`` -- the PURE, offline, per-bundle
    verifier this artifact shape actually calls for. This is deliberately
    NOT ``stranger_verify_bundle.py``'s ledger-DIR ``verify_bundle`` (same
    function name, different signature and purpose): that one needs a full
    COPY of a ledger directory on disk, which this route never hands out --
    it returns digests-only ``Bundle`` objects, the bundle tier's own
    standalone-verifiable shape (see ``evidence_server.py``'s module
    docstring for the exact scope split, including the known limit that a
    bundle never carries a Rust-producer capsule's own detached
    ``signed-statements/<capsule_id>.cose``);
  * a Refusal -> ``capsule_emit.evidence_request.verify_refusal_offline`` --
    a signed decline or a signed "recorded absence", either way citable
    offline against the peer's own key, never a bare unsigned 404.

Also renders a small "history card" -- ``continuity``/``history_depth``/
``unforked`` -- folded from the returned bundle's OWN ``checkpoint``/
``prior_checkpoint``/``checkpoint_cose`` fields via ``history_card.
build_history_card`` (reused unchanged, never re-derived): every bundle in
one Artifact answers under the SAME covering checkpoint (``answer()``'s
``expected_pin`` check enforces that whenever a pin was supplied), so the
first bundle alone already carries the (at most two-checkpoint) segment
this response proves.

Usage:
    python3 ask_history.py <peer-base-url> --subject range --selector <sel> \\
        [--expected-pin-root <hex> --expected-pin-mmr-size <int>] \\
        [--capsule-id <cid>] [--node-id <label>] [--tamper-check]

``--subject record --capsule-id <cid>`` asks for one record instead of a
range. ``--tamper-check`` proves the negative end to end: flips one byte of
the FIRST returned bundle's receipt in memory (never touching the peer) and
confirms ``verify_bundle`` now reports not-ok -- raises if it doesn't.

``--via mesh <peer-id>`` -- for a peer with no reachable ``evidence_server.py``
HTTP door (e.g. relay-only mesh peers): the first positional argument becomes
a hex mesh peer id instead of a base URL, and the request rides THIS node's
own admission-policy plugin's plugin-mesh-stream carrier
(``mesh_evidence_bridge``, channel ``evidence-request/1``) instead of a
direct HTTP POST -- reached locally via ``--local-host-api`` (the mesh-llm
host's own API port, default ``http://127.0.0.1:8080``). Verification is
IDENTICAL either way: this module never trusts the carrier, only the
response bytes.

**Paging a ``range`` subject.** A door that caps/pages its ``range``
answers (``capsule_emit.evidence_request.answer()``, once a node's
capsule-emit floor carries that fix) returns ``next_page_token`` on a
partial :class:`~capsule_emit.evidence_request.Artifact`. ``--subject
range`` follows it automatically, POSTing ``page: {token: ...}`` each
round until a page carries none, and renders the FULL concatenated bundle
list -- never silently stopping at the first page. A door that predates
paging never sets ``next_page_token``, so this loop runs exactly once
against it, unchanged. ``--max-pages`` (default 1000) bounds the loop so a
misbehaving door handing back an ever-repeating token cannot hang this
client forever.

``--subject references`` -- ``[mesh-ask-the-references]``, discovery
mechanism 1: how a STRANGER finds a verdict about node ``X`` that ``X``
itself won't hold (a pruned/declined record never reaches ``X``'s own
chain -- see ``adjudication_delivery.seal_adjudication_ack_refused``), with
no new trusted party. ``peer`` is ``X``'s own evidence door; ``--x-node-id``
is ``X``'s stable identity (the ``value`` a ``correlation`` ask names, and
the seed for deterministic sampling); ``--x-selector`` names which of
``X``'s own records to pull (digest tier, a plain ``range`` ask -- there is
no evidence-door subject for "give me everything", so the caller supplies
the region of interest, same as any other ``range`` ask); ``--peer-map``
is a local JSON ``{node_id: base_url}`` address book for reaching each
sampled counterparty's own door (plumbing, not a trust party -- nobody's
verdict is taken on the address book's say-so).

The flow: (1) pull ``X``'s own ``range`` at ``x_selector`` and read every
counterparty node id ``X``'s own records name (``requesting_party`` /
``served_by_node_id`` / ``counterparty_ref``, wherever a producer nested
them); (2) deterministically sample ``--k`` (default 3) of them, keyed on
``x_node_id`` alone (see :func:`sample_reference_candidates`) so two
independent strangers running this against the same ``X`` converge on the
same sample without coordinating; (3) ask each sampled counterparty's own
door ``correlation{by: counterparty, value: x_node_id}``; (4) verify every
returned bundle OFFLINE (:func:`verify_bundle`, the same full check
``render_artifact`` runs) before trusting anything in it -- an unverified
bundle contributes to nothing; (5) fold verified adjudication/ack-refusal
content into tallies, and separately check ``X``'s OWN pulled records for
per-counterparty sequence continuity (:func:`sequence_counter
.verify_pair_continuity`) -- a mid-sequence gap surfaces even if ``X``
never admits what filled it. Refusals are counted as answers, never
inferred from; nothing here is ever folded into a score.
"""
from __future__ import annotations

import argparse
import functools
import hashlib
import json
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from capsule_emit.bundle import Bundle, verify_bundle
from capsule_emit.evidence_request import Refusal, verify_refusal_offline

from history_card import build_history_card, with_references
from sequence_counter import verify_pair_continuity

__all__ = [
    "DEFAULT_REFERENCE_K",
    "ReferencesResult",
    "discover_counterparties",
    "fetch_all_pages",
    "main",
    "post_evidence_request",
    "post_mesh_evidence_request",
    "render_artifact",
    "render_references_result",
    "render_refusal",
    "run_references",
    "sample_reference_candidates",
]

#: Verdict vocabulary, mirrored from `twin_adjudicator`'s public constants --
#: named locally rather than importing that module (whose comparison/margin
#: machinery this CLI never needs) just to reach three strings, same
#: precedent `adjudication_delivery.py`'s own reason constants cite.
_VERDICT_CORROBORATED = "corroborated"
_VERDICT_INCONCLUSIVE = "inconclusive"
_VERDICT_CONTRADICTED_PREFIX = "contradicted:"

#: Fields a mesh capsule may name a counterparty node under -- free-form
#: `compute_attestation` extension data, not a fixed schema position (same
#: reason `capsule_emit.evidence_request`'s own `_CORRELATION_KEY_ALIASES`
#: walks generically rather than assuming one path).
_COUNTERPARTY_NAMING_KEYS = frozenset({"requesting_party", "served_by_node_id", "counterparty_ref"})

#: Default sample size for `references` -- k=3, per [mesh-ask-the-references].
DEFAULT_REFERENCE_K = 3


def _build_request_map(
    *,
    subject_kind: str,
    capsule_id: str | None,
    selector: str | None,
    expected_pin_root: str | None,
    expected_pin_mmr_size: int | None,
    nonce: str | None,
    page_token: str | None = None,
    correlation_by: str | None = None,
    correlation_value: str | None = None,
) -> dict[str, Any]:
    if subject_kind == "record":
        subject: dict[str, Any] = {"kind": "record", "capsule_id": capsule_id}
    elif subject_kind == "correlation":
        subject = {"kind": "correlation", "by": correlation_by, "value": correlation_value}
    else:
        subject = {"kind": "range", "selector": selector}
    coverage: dict[str, Any] = {}
    if expected_pin_root is not None and expected_pin_mmr_size is not None:
        coverage["expected_pin"] = {"root": expected_pin_root, "mmr_size": expected_pin_mmr_size}
    request: dict[str, Any] = {"subject": subject, "coverage": coverage}
    if nonce is not None:
        request["nonce"] = nonce
    if page_token is not None:
        request["page"] = {"token": page_token}
    return request


def fetch_all_pages(post: Any, request_map: dict[str, Any], *, max_pages: int = 1000) -> dict[str, Any]:
    """POST ``request_map`` via ``post`` (a zero-arg-besides-the-map
    callable, e.g. ``functools.partial(post_evidence_request, peer)``),
    then follow ``next_page_token`` until a page carries none, returning
    one merged payload -- all pages' ``bundles`` concatenated, in order.
    A :class:`Refusal` payload (has ``reason``, not ``bundles``) never
    pages; returned as-is from the first (only) round.
    """
    payload = post(request_map)
    if "reason" in payload:
        return payload

    bundles = list(payload["bundles"])
    pages = 1
    token = payload.get("next_page_token")
    while token is not None:
        if pages >= max_pages:
            raise RuntimeError(f"evidence door kept paging past --max-pages={max_pages}; refusing to loop forever")
        next_request = dict(request_map)
        next_request["page"] = {"token": token}
        next_payload = post(next_request)
        if "reason" in next_payload:
            # A refusal mid-pagination (e.g. the ledger shrank between
            # rounds) ends the walk with what was already collected --
            # never silently discarded, never a hang.
            break
        bundles.extend(next_payload["bundles"])
        pages += 1
        token = next_payload.get("next_page_token")

    merged = dict(payload)
    merged["bundles"] = bundles
    merged.pop("next_page_token", None)
    return merged


def post_evidence_request(peer_base_url: str, request_map: dict[str, Any]) -> dict[str, Any]:
    """POST ``request_map`` to ``<peer_base_url>/evidence-request``; return
    the parsed JSON response -- the raw Artifact-or-Refusal dict,
    unmodified."""
    body = json.dumps(request_map).encode("utf-8")
    url = peer_base_url.rstrip("/") + "/evidence-request"
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def post_mesh_evidence_request(
    local_host_api: str, plugin_name: str, peer_id: str, request_map: dict[str, Any]
) -> dict[str, Any]:
    """The mesh carrier for a peer with no reachable ``evidence_server.py``
    HTTP door (e.g. relay-only): ask THIS node's own admission-policy plugin
    to carry ``request_map`` to ``peer_id`` over the plugin mesh stream
    (``mesh_evidence_bridge::handle_mesh_evidence_request``, channel
    ``evidence-request/1``), via the plugin's ``mesh_evidence_request`` tool,
    reached locally through mesh-llm's own
    ``POST /api/plugins/<name>/tools/<tool>`` tool-call route -- never a new
    host route, never new host code. Returns the peer's own Artifact-or-
    Refusal dict unmodified, same as ``post_evidence_request``; a peer that
    never declared the channel surfaces as a non-2xx ``urllib.error.HTTPError``
    (the plugin's bounded wait timed out), never a hang.
    """
    body = json.dumps({"peer_id": peer_id, "request": request_map}).encode("utf-8")
    url = f"{local_host_api.rstrip('/')}/api/plugins/{plugin_name}/tools/mesh_evidence_request"
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def _iter_values_by_key(obj: Any, keys: frozenset[str]) -> list[str]:
    """Recursively walk *obj* (a JSON-decoded capsule receipt) and collect
    every string value found under a key in *keys*, at any depth --
    duplicated from (never reached into)
    ``capsule_emit.evidence_request``'s private helper of the same shape,
    same precedent ``evidence_responder.py``'s ``_refuse_served_summary``
    cites for not reaching into a sibling package's private function."""
    found: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in keys and isinstance(v, str):
                found.append(v)
            found.extend(_iter_values_by_key(v, keys))
    elif isinstance(obj, list):
        for item in obj:
            found.extend(_iter_values_by_key(item, keys))
    return found


def _iter_dicts_by_key(obj: Any, key: str) -> list[dict[str, Any]]:
    """Like :func:`_iter_values_by_key`, but collects dict VALUES found
    under *key* at any depth."""
    found: list[dict[str, Any]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == key and isinstance(v, dict):
                found.append(v)
            found.extend(_iter_dicts_by_key(v, key))
    elif isinstance(obj, list):
        for item in obj:
            found.extend(_iter_dicts_by_key(item, key))
    return found


def discover_counterparties(bundles: list[Bundle], *, exclude_node_id: str) -> list[str]:
    """From ``X``'s own already-verified digest-tier bundles (each
    ``Bundle.receipt`` is the raw ledger entry -- structural attestation
    fields only, never a disclosed payload), collect every distinct node
    identity ``X``'s OWN records name as a counterparty. Excludes ``X``
    itself and the honest ``"unknown"`` marker -- never a fabricated
    candidate. Sorted, so the result is a pure function of the bundle set.
    """
    found: set[str] = set()
    for b in bundles:
        for v in _iter_values_by_key(b.receipt, _COUNTERPARTY_NAMING_KEYS):
            if v and v not in (exclude_node_id, "unknown"):
                found.add(v)
    return sorted(found)


def sample_reference_candidates(
    candidates: list[str], *, subject_node_id: str, k: int = DEFAULT_REFERENCE_K
) -> list[str]:
    """Deterministic sample of ``min(k, len(candidates))``, seeded ONLY by
    ``subject_node_id`` (``X``'s own identity) -- a pure function of ``(X,
    the candidate set)``, never of who is asking or of any randomness. Two
    independent strangers who discover the same candidate set for the same
    ``X`` always pick the same sample without coordinating, exactly the
    property ``[mesh-ask-the-references]`` calls for."""
    uniq = sorted(set(candidates))
    ranked = sorted(uniq, key=lambda c: hashlib.sha256(f"{subject_node_id}:{c}".encode()).hexdigest())
    return ranked[:k]


def _classify_receipt_for_x(receipt: dict[str, Any], x_node_id: str, tally: dict[str, int]) -> None:
    """Fold one verified reference receipt's adjudication content into
    *tally* (mutated in place: ``corroborated``/``contradicted``/
    ``inconclusive``/``ack_refusals``). Only a verdict that actually NAMES
    ``x_node_id`` (the ``contradicted:<owner_id>`` shape) is ever attributed
    to it -- ``corroborated``/``inconclusive`` verdicts name no owner at all
    (``twin_adjudicator``'s own trust-model choice: disagreement is a
    trigger, not evidence of who is right) and so can never legitimately
    land in these per-``X`` buckets; the counters exist so a shape that DOES
    start naming an owner on those verdicts is picked up automatically, with
    no code change here.
    """
    for adjudication in _iter_dicts_by_key(receipt, "adjudication"):
        verdict = adjudication.get("verdict")
        if verdict == f"{_VERDICT_CONTRADICTED_PREFIX}{x_node_id}":
            tally["contradicted"] += 1
        elif verdict == _VERDICT_CORROBORATED:
            tally["corroborated"] += 1
        elif verdict == _VERDICT_INCONCLUSIVE:
            tally["inconclusive"] += 1
    for ack_refused in _iter_dicts_by_key(receipt, "adjudication_ack_refused"):
        if ack_refused.get("verdict") == f"{_VERDICT_CONTRADICTED_PREFIX}{x_node_id}":
            tally["ack_refusals"] += 1


@dataclass
class ReferencesResult:
    """Total outcome of :func:`run_references` -- an ACCOUNT of what was
    asked and found, never a score. ``continuity`` carries one
    ``{"continuity", "gaps_detected", "records_checked"}`` dict (see
    ``sequence_counter.PairContinuity``) per ``(x_node_id, *)`` pair found
    in ``X``'s own pulled records. ``gaps_detected`` is reported
    SEPARATELY from ``continuity`` -- a dropped-prefix gap does not by
    itself flip ``continuity`` to ``"broken"`` (``PairContinuity``'s own
    discipline: a gap and a regression are different findings), so a
    caller that only reads ``continuity`` would miss exactly the
    ``[mesh-ask-the-references]`` prune mutant this field exists to catch.
    """

    x_node_id: str
    candidates_discovered: int
    references_asked: int
    references_answered: int
    adjudications_about_x: dict[str, int]
    ack_refusals_about_x: int
    continuity: dict[str, dict[str, Any]] = field(default_factory=dict)
    unreachable_references: list[str] = field(default_factory=list)
    #: X's own history card (folded from X's pulled checkpoint fields, per
    #: ``history_card.build_history_card``), with this result's counts
    #: folded in via ``history_card.with_references``. ``None`` when X's
    #: pulled range carried no bundles to fold a checkpoint from.
    history_card: Any = None


def run_references(
    x_peer: str,
    *,
    x_node_id: str,
    x_selector: str,
    peer_map: dict[str, str],
    k: int = DEFAULT_REFERENCE_K,
    via: str = "http",
    local_host_api: str = "http://127.0.0.1:8080",
    local_plugin_name: str = "admission-policy",
    max_pages: int = 1000,
) -> ReferencesResult:
    """Discovery mechanism 1, end to end -- see the module docstring's
    ``--subject references`` section for the full flow. Raises
    ``RuntimeError`` only if ``X``'s own door refuses the initial pull
    (there is nothing to sample counterparties from); every OTHER failure
    (an unreachable or refusing reference) degrades into
    ``unreachable_references`` / a non-answer, never an exception -- a
    reference that won't talk is itself an honest, countable outcome.
    """
    if via == "mesh":
        x_post = functools.partial(post_mesh_evidence_request, local_host_api, local_plugin_name, x_peer)
    else:
        x_post = functools.partial(post_evidence_request, x_peer)

    x_request = _build_request_map(
        subject_kind="range",
        capsule_id=None,
        selector=x_selector,
        expected_pin_root=None,
        expected_pin_mmr_size=None,
        nonce=None,
    )
    x_payload = fetch_all_pages(x_post, x_request, max_pages=max_pages)
    if "reason" in x_payload:
        raise RuntimeError(f"could not pull {x_node_id}'s own records at selector={x_selector!r}: {x_payload['reason']}")

    x_bundles = [Bundle.from_dict(bd) for bd in x_payload["bundles"]]
    verified_x_receipts = []
    for b in x_bundles:
        ok, _errors = verify_bundle(b)
        if ok:
            verified_x_receipts.append(b.receipt)

    candidates = discover_counterparties(x_bundles, exclude_node_id=x_node_id)
    sampled = sample_reference_candidates(candidates, subject_node_id=x_node_id, k=k)

    tally = {"corroborated": 0, "contradicted": 0, "inconclusive": 0, "ack_refusals": 0}
    answered = 0
    unreachable: list[str] = []

    for node_id in sampled:
        base_url = peer_map.get(node_id)
        if not base_url:
            unreachable.append(node_id)
            continue
        reference_request = _build_request_map(
            subject_kind="correlation",
            capsule_id=None,
            selector=None,
            expected_pin_root=None,
            expected_pin_mmr_size=None,
            nonce=None,
            correlation_by="counterparty",
            correlation_value=x_node_id,
        )
        try:
            payload = fetch_all_pages(
                functools.partial(post_evidence_request, base_url), reference_request, max_pages=max_pages
            )
        except urllib.error.URLError:
            unreachable.append(node_id)
            continue

        answered += 1
        if "reason" in payload:
            # A signed refusal (incl. no_such_record) IS an answer -- counted
            # above, never treated as a non-response, and never inferred as
            # evidence either way.
            continue

        for bd in payload["bundles"]:
            bundle = Bundle.from_dict(bd)
            ok, _errors = verify_bundle(bundle)
            if not ok:
                # Never trust an unverified bundle's content -- contributes
                # to nothing.
                continue
            _classify_receipt_for_x(bundle.receipt, x_node_id, tally)

    continuity_by_pair = verify_pair_continuity(verified_x_receipts)
    continuity = {
        pair: {
            "continuity": pc.continuity,
            "gaps_detected": pc.gaps_detected,
            "records_checked": pc.records_checked,
        }
        for pair, pc in continuity_by_pair.items()
        if pair.startswith(f"{x_node_id}::")
    }
    adjudications_about_x = {
        "corroborated": tally["corroborated"],
        "contradicted": tally["contradicted"],
        "inconclusive": tally["inconclusive"],
    }

    card = _build_history_card_from_bundles(x_bundles, node_id=x_node_id)
    if card is not None:
        card = with_references(
            card,
            references_asked=len(sampled),
            references_answered=answered,
            adjudications_about_x=adjudications_about_x,
            ack_refusals_about_x=tally["ack_refusals"],
        )

    return ReferencesResult(
        x_node_id=x_node_id,
        candidates_discovered=len(candidates),
        references_asked=len(sampled),
        references_answered=answered,
        adjudications_about_x=adjudications_about_x,
        ack_refusals_about_x=tally["ack_refusals"],
        continuity=continuity,
        unreachable_references=unreachable,
        history_card=card,
    )


def render_references_result(result: ReferencesResult) -> str:
    lines = [
        (
            f"REFERENCES x={result.x_node_id} candidates_discovered={result.candidates_discovered} "
            f"asked={result.references_asked} answered={result.references_answered}"
        ),
        f"  adjudications_about_x={result.adjudications_about_x} ack_refusals_about_x={result.ack_refusals_about_x}",
    ]
    if result.unreachable_references:
        lines.append(f"  unreachable references: {', '.join(result.unreachable_references)}")
    if result.continuity:
        lines.append("  X's own chain, per counterparty pair:")
        lines.extend(f"    {pair}: {continuity}" for pair, continuity in sorted(result.continuity.items()))
    else:
        lines.append("  X's own chain: no counterparty-pair-sequenced records in the pulled range")
    if result.history_card is not None:
        props = result.history_card.properties
        lines.append(
            f"  X's history card: continuity={props.continuity!r} history_depth={props.history_depth} "
            f"unforked={props.unforked} references={result.history_card.to_value()['references']}"
        )
    return "\n".join(lines)


def render_refusal(payload: dict[str, Any]) -> str:
    refusal = Refusal(
        request_digest=payload["request_digest"],
        reason=payload["reason"],
        issued_at=payload["issued_at"],
        key_id=payload["key_id"],
        sig=payload["sig"],
    )
    verified = verify_refusal_offline(refusal)
    return "\n".join(
        [
            f"REFUSAL reason={refusal.reason} issued_at={refusal.issued_at} key_id={refusal.key_id}",
            f"signature verifies offline: {verified}",
        ]
    )


def _build_history_card_from_bundles(bundles: list[Bundle], *, node_id: str) -> Any:
    """Fold a response's own ``checkpoint``/``prior_checkpoint``/
    ``checkpoint_cose`` fields (the first bundle alone already carries the
    covering, at-most-two-checkpoint segment -- see the module docstring)
    into a :class:`history_card.HistoryCard`. Returns ``None`` when
    ``bundles`` is empty -- no checkpoint fields to fold."""
    if not bundles:
        return None
    b = bundles[0]
    checkpoint_lines: list[dict[str, Any]] = []
    since_size = 0
    if b.prior_checkpoint is not None:
        checkpoint_lines.append(b.prior_checkpoint.to_dict())
        since_size = b.prior_checkpoint.mmr_size
    current = b.checkpoint.to_dict()
    if b.checkpoint_cose is not None:
        current["checkpoint_cose"] = b.checkpoint_cose.hex()
    checkpoint_lines.append(current)

    return build_history_card(
        node_id=node_id,
        log_id=b.checkpoint.log_id,
        checkpoint_lines=checkpoint_lines,
        since_size=since_size,
    )


def _history_card_lines(bundles: list[Bundle], *, node_id: str) -> list[str]:
    card = _build_history_card_from_bundles(bundles, node_id=node_id)
    if card is None:
        return []
    props = card.properties
    return [
        "history card (folded from this response's own checkpoint fields):",
        f"    continuity={props.continuity!r} history_depth={props.history_depth} unforked={props.unforked}",
        f"    checkpoint_count={card.checkpoint_count} witnessed={card.witnessed}",
    ]


def render_artifact(payload: dict[str, Any], *, node_id: str, tamper_check: bool = False) -> str:
    bundles = [Bundle.from_dict(bd) for bd in payload["bundles"]]
    lines = [f"ARTIFACT subject_kind={payload['subject_kind']} bundles={len(bundles)}"]
    for b in bundles:
        ok, errors = verify_bundle(b)
        lines.append(f"  bundle {b.capsule_id}: log-integrity verify_bundle.ok={ok}")
        lines.extend(f"      {e}" for e in errors)
        lines.append(
            "      NOTE: bundle-tier evidence proves LOG integrity (inclusion, checkpoint "
            "signature/consistency), never a Rust-producer capsule's own detached "
            "signed-statement (signed-statements/<capsule_id>.cose is not carried in this "
            "artifact shape) -- see evidence_server.py's module docstring."
        )

    lines.extend(_history_card_lines(bundles, node_id=node_id))

    if tamper_check and bundles:
        tampered = json.loads(json.dumps(payload["bundles"][0]))
        tampered["receipt"] = {**tampered["receipt"], "capsule_id": "0" * 64}
        tampered_ok, _tampered_errors = verify_bundle(Bundle.from_dict(tampered))
        lines.append(f"tamper-check (flipped receipt.capsule_id in memory): verify.ok={tampered_ok} (expected False)")
        if tampered_ok:
            raise AssertionError("tamper-check FAILED to be detected -- verify_bundle did not flip")

    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "peer",
        help="peer's evidence_server.py base URL (default) or, with --via mesh, the peer's hex mesh peer id",
    )
    parser.add_argument("--subject", choices=["record", "range", "references"], default="range")
    parser.add_argument("--capsule-id", default=None, help="required for --subject record")
    parser.add_argument("--selector", default=None, help="required for --subject range, e.g. id1..id2")
    parser.add_argument(
        "--x-node-id",
        default=None,
        help="required for --subject references: X's stable identity (peer is X's own evidence door)",
    )
    parser.add_argument(
        "--x-selector",
        default=None,
        help="required for --subject references: which of X's own records to pull, e.g. id1..id2",
    )
    parser.add_argument(
        "--peer-map",
        default=None,
        help="required for --subject references: JSON file {node_id: base_url} for reaching each "
        "sampled counterparty's own evidence door",
    )
    parser.add_argument(
        "--k",
        type=int,
        default=DEFAULT_REFERENCE_K,
        help="--subject references only: how many of X's counterparties to sample (default 3)",
    )
    parser.add_argument("--expected-pin-root", default=None)
    parser.add_argument("--expected-pin-mmr-size", type=int, default=None)
    parser.add_argument("--nonce", default=None)
    parser.add_argument("--node-id", default="requester", help="label only, for the rendered history card")
    parser.add_argument(
        "--tamper-check", action="store_true", help="prove a corrupted COPY of the response fails verify"
    )
    parser.add_argument(
        "--via",
        choices=["http", "mesh"],
        default="http",
        help="http (default): POST peer directly. mesh: carry the request over THIS node's own "
        "admission-policy plugin's plugin-mesh-stream (for peers with no reachable HTTP door).",
    )
    parser.add_argument(
        "--local-host-api",
        default="http://127.0.0.1:8080",
        help="--via mesh only: this node's own mesh-llm host API base URL",
    )
    parser.add_argument(
        "--local-plugin-name",
        default="admission-policy",
        help="--via mesh only: the plugin name carrying the request (its /tools/mesh_evidence_request route)",
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=1000,
        help="cap on how many next_page_token rounds to follow for a range subject (default 1000)",
    )
    args = parser.parse_args(argv)

    if args.subject == "record" and not args.capsule_id:
        parser.error("--subject record requires --capsule-id")
    if args.subject == "range" and not args.selector:
        parser.error("--subject range requires --selector")
    if args.subject == "references" and not (args.x_node_id and args.x_selector and args.peer_map):
        parser.error("--subject references requires --x-node-id, --x-selector, and --peer-map")

    if args.subject == "references":
        with open(args.peer_map, encoding="utf-8") as fh:
            peer_map = json.load(fh)
        try:
            result = run_references(
                args.peer,
                x_node_id=args.x_node_id,
                x_selector=args.x_selector,
                peer_map=peer_map,
                k=args.k,
                via=args.via,
                local_host_api=args.local_host_api,
                local_plugin_name=args.local_plugin_name,
                max_pages=args.max_pages,
            )
        except (RuntimeError, urllib.error.URLError) as exc:
            print(f"references {args.x_node_id!r} via {args.peer} (via {args.via}) failed: {exc}", file=sys.stderr)
            return 1
        print(render_references_result(result))
        return 0

    request_map = _build_request_map(
        subject_kind=args.subject,
        capsule_id=args.capsule_id,
        selector=args.selector,
        expected_pin_root=args.expected_pin_root,
        expected_pin_mmr_size=args.expected_pin_mmr_size,
        nonce=args.nonce,
    )
    if args.via == "mesh":
        post = functools.partial(post_mesh_evidence_request, args.local_host_api, args.local_plugin_name, args.peer)
    else:
        post = functools.partial(post_evidence_request, args.peer)

    try:
        payload = fetch_all_pages(post, request_map, max_pages=args.max_pages)
    except urllib.error.URLError as exc:
        print(f"request to {args.peer} (via {args.via}) failed: {exc}", file=sys.stderr)
        return 1

    if "reason" in payload:
        print(render_refusal(payload))
        return 0
    print(render_artifact(payload, node_id=args.node_id, tamper_check=args.tamper_check))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
