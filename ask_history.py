#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""``ask_history.py`` -- the requester side of the evidence request exchange
(``draft-mih-agent-evidence-request-00``).

Builds a -00 request, sends it to a peer (``evidence_server.py``'s
``POST /evidence-request``, or over the mesh with ``--via mesh``), and
checks whatever comes back OFFLINE, from the reply alone, with
``agent_action_capsule.evidence_request``:

  * an artifact arrives in the interop profile's signed envelope (§6.2):
    :func:`read_reply` checks its signature, that the artifact and each item
    of verification material hash to their signed digests, that it answers
    the request sent (``request_digest``), and, when a key is pinned
    (``--responder-key``), that the responder signed it. Checkpointed Local
    Log material, when an envelope carries it, is checked as the profile's
    ``anchor_inclusion`` (``check_cll_material``);
  * a refusal is checked as signed, conformant and answering the request
    sent -- a signed decline is the responder's act, citable offline, never
    a bare unsigned 404.

The artifact of a mesh responder is ``{anchor, evidence_stream, subject,
bundles}`` (see ``evidence_responder.py``): each bundle is checked with
``capsule_emit.bundle.verify_bundle`` and must be proven under the anchor the
envelope names (its ``checkpoint_cose`` hashes to the anchor digest). For a
Rust-produced capsule a bundle proves LOG integrity (inclusion, the
checkpoint's signature and consistency), not the capsule's own detached
signed statement, which the bundle does not carry; the rendering says so.

Also renders a small "history card" -- ``continuity``/``history_depth``/
``unforked`` -- folded from the first bundle's ``checkpoint``/
``prior_checkpoint``/``checkpoint_cose`` via ``history_card
.build_history_card`` (every bundle in one answer is under the same anchor),
or from the checkpoint lines of a ``checkpoints`` answer.

Usage:
    python3 ask_history.py <peer-base-url> --subject record --capsule-id <cid>
    python3 ask_history.py <peer-base-url> --subject range --range <a> <b>
    python3 ask_history.py <peer-base-url> --subject full_history | checkpoints
    python3 ask_history.py <peer-base-url> --subject correlation --correlation <id>

Coverage is exactly one of ``--expected-pin <anchor digest>`` (the SHA-256 of
a checkpoint's COSE statement) and ``--min-freshness <size or RFC 3339 UTC
time>``; the default is ``--min-freshness 0``, the freshest anchor held.
``--tamper-check`` proves the negative end to end: it flips one byte of the
artifact and one field of the first bundle's receipt in memory (never
touching the peer) and confirms both checks then fail.

``--via mesh <peer-id>`` -- for a peer with no reachable HTTP door: the first
positional argument is a hex mesh peer id, and the request rides this node's
own Mesh-LLM plugin (``mesh_evidence_request`` tool, channel
``evidence-request/1``), reached through ``--local-host-api``. The plugin
may add members to the request (``requester_id``, ``requester_auth``) before
it sends it, so the request digest checked is the one the plugin reports for
the bytes it sent. Verification is otherwise IDENTICAL: nothing here trusts
the carrier, only the reply.

``--subject references`` -- ``[mesh-ask-the-references]``, discovery
mechanism 1: how a STRANGER finds a verdict about node ``X`` that ``X``
itself won't hold (a declined record never reaches ``X``'s own chain -- see
``adjudication_delivery.seal_adjudication_ack_refused``), with no new trusted
party. ``peer`` is ``X``'s own evidence door; ``--x-node-id`` is ``X``'s
stable identity (the correlation identifier a reference is asked about);
``--x-range`` names which of ``X``'s records to pull (all of them, under the
freshest anchor, when omitted); ``--peer-map`` is a local JSON ``{node_id:
base_url}`` address book for reaching each sampled counterparty's door
(plumbing, not a trust party).

The flow: (1) pull ``X``'s own records and read every counterparty node id
they name (``requesting_party`` / ``served_by_node_id`` /
``counterparty_ref``, wherever a producer nested them); (2)
deterministically sample ``--k`` (default 3) of them, seeded by the root of
a WITNESSED checkpoint in ``X``'s pulled records (see :func:`witnessed_seed`
/ :func:`sample_reference_candidates`), so two independent strangers
converge on the same sample without coordinating. Unlike ``X``'s node id,
that root is not known before the records it commits to are written, and
once witnessed it is fixed at a third party. The limit: ``X`` can still try
candidate record sets locally before any is witnessed. No witnessed
checkpoint means no sample, never a fallback to a seed ``X`` can predict.
The seed and its source are recorded in :attr:`ReferencesResult.selection`;
(3) ask each sampled counterparty's door ``{"correlation": x_node_id}``;
(4) verify every reply and every returned bundle OFFLINE before trusting
anything in it -- an unverified bundle contributes to nothing; (5) fold
verified adjudication/ack-refusal content into tallies, and separately check
``X``'s OWN pulled records for per-counterparty sequence continuity
(:func:`sequence_counter.verify_pair_continuity`). Refusals are counted as
answers, never inferred from; nothing here is ever folded into a score.
"""
from __future__ import annotations

import argparse
import dataclasses
import functools
import hashlib
import json
import sys
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from agent_action_capsule import evidence_request as er
from agent_action_capsule.canonical import jcs
from agent_action_capsule.interop_profile._common import FAIL, TrustPolicy
from capsule_emit.bundle import Bundle, verify_bundle
from capsule_emit.checkpoint import StampVerdict, verify_witness_stamp_tristate

from history_card import build_history_card, with_references
from sequence_counter import verify_pair_continuity
from witness_pin import default_witness_pin

__all__ = [
    "DEFAULT_REFERENCE_K",
    "Exchange",
    "ReferencesResult",
    "Reply",
    "WitnessedSeed",
    "artifact_bundles",
    "build_request",
    "candidates_digest",
    "discover_counterparties",
    "main",
    "post_evidence_request",
    "post_mesh_evidence_request",
    "read_reply",
    "render_artifact",
    "render_references_result",
    "render_refusal",
    "run_references",
    "sample_reference_candidates",
    "witnessed_seed",
]

#: Verdict vocabulary, mirrored from `twin_adjudicator`'s public constants --
#: named locally rather than importing that module (whose comparison/margin
#: machinery this CLI never needs) just to reach three strings, same
#: precedent `adjudication_delivery.py`'s own reason constants cite.
_VERDICT_CORROBORATED = "corroborated"
_VERDICT_INCONCLUSIVE = "inconclusive"
_VERDICT_CONTRADICTED_PREFIX = "contradicted:"

#: Fields a mesh capsule may name a counterparty node under -- free-form
#: `compute_attestation` extension data, not a fixed schema position.
_COUNTERPARTY_NAMING_KEYS = frozenset({"requesting_party", "served_by_node_id", "counterparty_ref"})

#: Default sample size for `references` -- k=3, per [mesh-ask-the-references].
DEFAULT_REFERENCE_K = 3


def build_request(
    subject: er.Subject,
    *,
    expected_pin: str | None = None,
    min_freshness: int | str | None = None,
    derivation: str | None = None,
    nonce: str | None = None,
) -> dict[str, Any]:
    """A -00 request map. Coverage is exactly one member: ``expected_pin``
    when given, else ``min_freshness`` (``0``, any anchor, by default)."""
    if expected_pin is not None and min_freshness is not None:
        raise ValueError("coverage is expected_pin or min_freshness, not both")
    coverage = {"expected_pin": expected_pin} if expected_pin is not None else {"min_freshness": min_freshness or 0}
    request: dict[str, Any] = {"subject": subject.to_wire(), "coverage": coverage}
    if derivation is not None:
        request["derivation"] = derivation
    if nonce is not None:
        request["nonce"] = nonce
    return request


@dataclass(frozen=True)
class Exchange:
    """One request sent and its reply: ``request_digest`` is the SHA-256 of
    the request bytes as sent (-00 §4.2), ``reply`` the reply's JSON."""

    request_digest: str
    reply: dict[str, Any]


#: A transport: sends a request map and returns the :class:`Exchange`.
Post = Callable[[dict[str, Any]], Exchange]


def post_evidence_request(peer_base_url: str, request_map: dict[str, Any], *, timeout: float = 30) -> Exchange:
    """POST ``request_map`` to ``<peer_base_url>/evidence-request``."""
    body = json.dumps(request_map, separators=(",", ":")).encode("utf-8")
    url = peer_base_url.rstrip("/") + "/evidence-request"
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return Exchange(er.request_digest(body), json.loads(resp.read()))


def post_mesh_evidence_request(
    local_host_api: str, plugin_name: str, peer_id: str, request_map: dict[str, Any]
) -> Exchange:
    """The mesh carrier, for a peer with no reachable HTTP door: ask this
    node's own plugin to carry ``request_map`` to ``peer_id`` over the
    ``evidence-request/1`` channel, through its ``mesh_evidence_request`` tool
    (``POST /api/plugins/<name>/tools/mesh_evidence_request``). A peer that
    never declared the channel surfaces as a non-2xx
    ``urllib.error.HTTPError``, never a hang.

    Two plugins answer this tool. The Mesh-LLM capsules plugin may add
    members and sign the request before sending it, so it reports
    ``{"answer", "request_digest", ...}``, the digest of the bytes it sent.
    This repo's admission-policy plugin returns the peer's reply as is, and
    sends the request as compact JSON in the order given
    (``serde_json::to_vec``), so the digest is of that encoding. If a
    carrier sent other bytes, :func:`read_reply` reports a reply to another
    request: never a silent pass."""
    body = json.dumps({"peer_id": peer_id, "request": request_map}).encode("utf-8")
    url = f"{local_host_api.rstrip('/')}/api/plugins/{plugin_name}/tools/mesh_evidence_request"
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=30) as resp:
        result = json.loads(resp.read())
    if not isinstance(result, dict):
        raise TypeError("the mesh carrier's answer is not a JSON object")
    if isinstance(result.get("answer"), dict) and er.is_digest(result.get("request_digest")):
        return Exchange(result["request_digest"], result["answer"])
    sent = json.dumps(request_map, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return Exchange(er.request_digest(sent), result)


@dataclass(frozen=True)
class Reply:
    """What :func:`read_reply` made of a reply. ``ok`` is false iff a check
    failed; ``errors`` names each failure. Exactly one of ``envelope`` and
    ``refusal`` is set unless the reply could not be read at all."""

    ok: bool
    errors: tuple[str, ...]
    envelope: er.Envelope | None = None
    refusal: er.Refusal | None = None
    #: The artifact's JSON, when it is JSON.
    body: Any = None
    #: The profile's ``anchor_inclusion`` for Checkpointed Local Log
    #: material, when the envelope carries any.
    cll: Any = None


def read_reply(exchange: Exchange, *, responder_key: str | None = None, trust: TrustPolicy | None = None) -> Reply:
    """Read and check a reply offline (see the module docstring). Never
    raises for any reply."""
    errors: list[str] = []
    try:
        parsed = er.parse_reply(json.dumps(exchange.reply).encode("utf-8"), "json")
    except (er.VerificationError, TypeError, ValueError) as exc:
        return Reply(ok=False, errors=(f"not a reply: {exc}",))

    if isinstance(parsed, er.Refusal):
        if not er.verify_refusal_offline(parsed):
            errors.append("the refusal's signature does not verify")
        elif not er.check_refusal(parsed.to_dict()).conformant:
            errors.append(f"the refusal is signed but not conformant (reason {parsed.reason!r})")
        if parsed.request_digest != exchange.request_digest:
            errors.append("the refusal answers another request")
        if responder_key is not None and parsed.key_id != responder_key:
            errors.append("the refusal is signed by another key than the responder's")
        return Reply(ok=not errors, errors=tuple(errors), refusal=parsed)

    envelope = parsed
    try:
        envelope.verify()
    except er.VerificationError as exc:
        errors.append(f"envelope: {exc}")
    if envelope.profile != er.PROFILE:
        errors.append(f"envelope profile is {envelope.profile!r}, not {er.PROFILE}")
    if envelope.request_digest != exchange.request_digest:
        errors.append("the envelope answers another request")
    if responder_key is not None and envelope.responder != responder_key:
        errors.append("the envelope is signed by another key than the responder's")
    cll = None
    if envelope.verification:
        cll = er.check_cll_material(envelope, trust or TrustPolicy())
        if cll.status == FAIL:
            errors.append(f"anchor inclusion fails: {cll.detail}")
    try:
        body = json.loads(envelope.artifact)
    except (UnicodeDecodeError, ValueError):
        body = None
    return Reply(ok=not errors, errors=tuple(errors), envelope=envelope, body=body, cll=cll)


def artifact_bundles(reply: Reply) -> tuple[list[Bundle], list[str]]:
    """The bundles of a mesh artifact (see ``evidence_responder.py``), and the
    problems found reading them. Each must be proven under the anchor the
    envelope names: its ``checkpoint_cose`` hashes to the anchor digest.
    A bundle failing that is left out; ``verify_bundle`` is the caller's."""
    body = reply.body
    if not isinstance(body, dict) or not isinstance(body.get("bundles"), list):
        return [], ["the artifact is not a set of bundles"]
    anchor = reply.envelope.anchor_digest if reply.envelope is not None else None
    bundles: list[Bundle] = []
    problems: list[str] = []
    for i, bd in enumerate(body["bundles"]):
        try:
            b = Bundle.from_dict(bd)
        except (KeyError, TypeError, ValueError) as exc:
            problems.append(f"bundle {i} is not a bundle: {exc}")
            continue
        if b.checkpoint_cose is None or hashlib.sha256(b.checkpoint_cose).hexdigest() != anchor:
            problems.append(f"bundle {b.capsule_id} is not proven under the envelope's anchor")
            continue
        bundles.append(b)
    return bundles, problems


def verified_bundles(reply: Reply) -> list[Bundle]:
    """The bundles of a checked reply that pass every check: the reply's own,
    the anchor binding and ``verify_bundle``. Empty for anything else."""
    if not reply.ok or reply.envelope is None:
        return []
    bundles, _problems = artifact_bundles(reply)
    return [b for b in bundles if verify_bundle(b)[0]]


def _iter_values_by_key(obj: Any, keys: frozenset[str]) -> list[str]:
    """Recursively walk *obj* (a JSON-decoded capsule receipt) and collect
    every string value found under a key in *keys*, at any depth."""
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


@dataclass(frozen=True)
class WitnessedSeed:
    """The reference-sample seed: the root of a checkpoint of ``X``'s own
    log whose witness receipt verifies (:attr:`StampVerdict.WITNESSED` --
    checkpoint-bound and signed under a pinned Transparency Service key),
    plus where it came from, so a stranger can recompute the sample."""

    root: str
    log_id: str
    mmr_size: int
    ts_url: str

    def to_value(self) -> dict[str, Any]:
        return {
            "source": "witnessed_checkpoint",
            "root": self.root,
            "log_id": self.log_id,
            "mmr_size": self.mmr_size,
            "ts_url": self.ts_url,
        }


def witnessed_seed(bundles: list[Bundle]) -> WitnessedSeed | None:
    """The latest (largest ``mmr_size``) checkpoint among ``X``'s own
    VERIFIED bundles' ``checkpoint``/``prior_checkpoint`` whose witness
    receipt re-verifies as :attr:`StampVerdict.WITNESSED`. A receipt is
    re-verified, never trusted for being present, and a producer-set
    ``is_stub`` flag counts for nothing. ``None`` when there is no such
    checkpoint -- the caller then draws no sample."""
    best: WitnessedSeed | None = None
    for b in bundles:
        ok, _errors = verify_bundle(b)
        if not ok:
            continue
        for cp in (b.prior_checkpoint, b.checkpoint):
            if cp is None or (best is not None and cp.mmr_size <= best.mmr_size):
                continue
            for w in cp.witnesses or []:
                verdict, _stamp_errors = verify_witness_stamp_tristate(
                    cp, w, ts_pubkey_pem=default_witness_pin(w.ts_url)
                )
                if verdict is StampVerdict.WITNESSED:
                    best = WitnessedSeed(root=cp.root, log_id=cp.log_id, mmr_size=cp.mmr_size, ts_url=w.ts_url)
                    break
    return best


def candidates_digest(candidates: list[str]) -> str:
    """SHA-256 of the JCS of the sorted, de-duplicated candidate set -- what
    the sample was drawn from, recorded beside the seed."""
    return hashlib.sha256(jcs(sorted(set(candidates)))).hexdigest()


def sample_reference_candidates(candidates: list[str], *, seed: str, k: int = DEFAULT_REFERENCE_K) -> list[str]:
    """Deterministic sample of ``min(k, len(candidates))``: candidates ranked
    by ``sha256(f"{seed}:{candidate}")``, lowest first. A pure function of
    ``(seed, the candidate set)``, never of who is asking or of any
    randomness, so independent strangers converge on the same sample.

    ``seed`` is :func:`witnessed_seed`'s root. It was ``X``'s own node id,
    which ``X`` knows before it writes a single record: ``X`` could compute
    its own sample in advance and shape it, by what it records or by
    grinding counterparty ids."""
    uniq = sorted(set(candidates))
    ranked = sorted(uniq, key=lambda c: hashlib.sha256(f"{seed}:{c}".encode()).hexdigest())
    return ranked[:k]


def _is_attributed_adjudication(adjudication: dict[str, Any]) -> bool:
    """[mesh-referee-attribution] Return True only when the adjudication
    block carries a non-empty ``referee_id`` field -- meaning the verdict was
    produced by an identified referee party whose identity was verified by
    ``adjudicate()`` before the capsule was sealed.  An unattributed
    adjudication (no ``referee_id``) cannot be trusted as an independent
    tiebreak, so ack_refusal tallies that reference one are not counted."""
    return bool(adjudication.get("referee_id"))


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

    [mesh-referee-attribution] ``ack_refusals`` are only counted when the
    referenced adjudication block carries an attributed ``referee_id`` --
    i.e. when the verdict that was refused originated from an identified
    referee.  An unattributed accusation (no ``referee_id``) predates the
    attribution requirement or was produced outside the verified pipeline and
    is not counted, so a forged unattributed ack_refusal does not inflate the
    tally.
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
            if _is_attributed_adjudication(ack_refused):
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
    #: How the sample was drawn, so anyone can recompute it:
    #: ``{"method": "seeded", "seed": WitnessedSeed.to_value(), "k",
    #: "candidates_digest"}``, or ``{"method": "not_sampled", "reason", "k",
    #: "candidates_digest"}`` when X's pulled range had no witnessed
    #: checkpoint to seed from.
    selection: dict[str, Any] = field(default_factory=dict)


def _post_for(peer: str, *, via: str, local_host_api: str, local_plugin_name: str) -> Post:
    if via == "mesh":
        return functools.partial(post_mesh_evidence_request, local_host_api, local_plugin_name, peer)
    return functools.partial(post_evidence_request, peer)


def run_references(
    x_peer: str,
    *,
    x_node_id: str,
    peer_map: dict[str, str],
    x_range: tuple[int, int] | None = None,
    k: int = DEFAULT_REFERENCE_K,
    via: str = "http",
    local_host_api: str = "http://127.0.0.1:8080",
    local_plugin_name: str = "admission-policy",
) -> ReferencesResult:
    """Discovery mechanism 1, end to end -- see the module docstring's
    ``--subject references`` section for the full flow. Raises
    ``RuntimeError`` only if ``X``'s own door refuses the initial pull, or
    its reply does not check out (there is nothing to sample counterparties
    from); every OTHER failure (an unreachable or refusing reference)
    degrades into ``unreachable_references`` / a non-answer, never an
    exception -- a reference that won't talk is itself an honest, countable
    outcome.
    """
    x_post = _post_for(x_peer, via=via, local_host_api=local_host_api, local_plugin_name=local_plugin_name)
    x_subject = er.Subject("range", x_range) if x_range is not None else er.Subject("full_history")
    x_reply = read_reply(x_post(build_request(x_subject)))
    if x_reply.refusal is not None:
        raise RuntimeError(f"could not pull {x_node_id}'s own records: refused {x_reply.refusal.reason}")
    if not x_reply.ok:
        raise RuntimeError(f"{x_node_id}'s own reply does not check out: {'; '.join(x_reply.errors)}")

    x_bundles = verified_bundles(x_reply)
    verified_x_receipts = [b.receipt for b in x_bundles]

    candidates = discover_counterparties(x_bundles, exclude_node_id=x_node_id)
    seed = witnessed_seed(x_bundles)
    selection: dict[str, Any] = {"k": k, "candidates_digest": candidates_digest(candidates)}
    if seed is None:
        sampled: list[str] = []
        selection.update(method="not_sampled", reason="no witnessed checkpoint in the pulled records to seed from")
    else:
        sampled = sample_reference_candidates(candidates, seed=seed.root, k=k)
        selection.update(method="seeded", seed=seed.to_value())

    tally = {"corroborated": 0, "contradicted": 0, "inconclusive": 0, "ack_refusals": 0}
    answered = 0
    unreachable: list[str] = []

    reference_request = build_request(er.Subject("correlation", x_node_id))
    for node_id in sampled:
        base_url = peer_map.get(node_id)
        if not base_url:
            unreachable.append(node_id)
            continue
        try:
            exchange = post_evidence_request(base_url, reference_request)
        except urllib.error.URLError:
            unreachable.append(node_id)
            continue

        answered += 1
        # A signed refusal (no_such_subject included) IS an answer -- counted
        # above, never inferred from either way. A reply that does not check
        # out contributes nothing.
        for bundle in verified_bundles(read_reply(exchange)):
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
        selection=selection,
    )


def render_references_result(result: ReferencesResult) -> str:
    lines = [
        (
            f"REFERENCES x={result.x_node_id} candidates_discovered={result.candidates_discovered} "
            f"asked={result.references_asked} answered={result.references_answered}"
        ),
        f"  adjudications_about_x={result.adjudications_about_x} ack_refusals_about_x={result.ack_refusals_about_x}",
    ]
    selection = result.selection
    if selection.get("method") == "seeded":
        seed = selection["seed"]
        lines.append(
            f"  sample: seeded by witnessed checkpoint root={seed['root']} "
            f"(log_id={seed['log_id']} mmr_size={seed['mmr_size']} witness={seed['ts_url']}) "
            f"k={selection['k']} candidates_digest={selection['candidates_digest']}"
        )
    elif selection:
        lines.append(f"  sample: none drawn -- {selection.get('reason')}")
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


def render_refusal(reply: Reply) -> str:
    refusal = reply.refusal
    lines = [
        f"REFUSAL reason={refusal.reason} issued_at={refusal.issued_at} key_id={refusal.key_id}",
        f"signed, conformant and answering this request: {reply.ok}",
    ]
    lines.extend(f"    {e}" for e in reply.errors)
    return "\n".join(lines)


def _checkpoints_lines(body: dict[str, Any], *, node_id: str) -> list[str]:
    lines_in = body.get("checkpoints")
    if not isinstance(lines_in, list) or not lines_in:
        return ["  the artifact carries no checkpoints"]
    out = [f"  checkpoints={len(lines_in)}"]
    try:
        card = build_history_card(node_id=node_id, log_id=body.get("evidence_stream", ""), checkpoint_lines=lines_in)
    except (KeyError, TypeError, ValueError) as exc:  # lines that do not fold are reported, not raised
        return [*out, f"  history card: could not fold these checkpoints: {exc}"]
    props = card.properties
    out.append(
        f"  history card: continuity={props.continuity!r} history_depth={props.history_depth} "
        f"unforked={props.unforked} witnessed={card.witnessed}"
    )
    return out


def render_artifact(reply: Reply, *, node_id: str, tamper_check: bool = False) -> str:
    envelope = reply.envelope
    (form,) = envelope.subject.to_wire()
    lines = [
        (
            f"ARTIFACT subject={form} anchor={envelope.anchor_digest} responder={envelope.responder} "
            f"issued_at={envelope.issued_at}"
        ),
        f"envelope verifies and answers this request: {reply.ok}",
    ]
    lines.extend(f"    {e}" for e in reply.errors)
    if reply.cll is not None:
        lines.append(f"  anchor_inclusion (Checkpointed Local Log material): {reply.cll.status}")

    body = reply.body if isinstance(reply.body, dict) else {}
    bundles: list[Bundle] = []
    if envelope.derivation is not None:
        lines.append(f"  derivation={envelope.derivation} members={sorted(body)}")
    elif "checkpoints" in body:
        lines.extend(_checkpoints_lines(body, node_id=node_id))
    elif "bundles" in body:
        bundles, problems = artifact_bundles(reply)
        lines.append(f"  bundles={len(body['bundles'])}")
        lines.extend(f"    {p}" for p in problems)
        for b in bundles:
            ok, errors = verify_bundle(b)
            lines.append(f"  bundle {b.capsule_id}: log-integrity verify_bundle.ok={ok}")
            lines.extend(f"      {e}" for e in errors)
        if bundles:
            lines.append(
                "  NOTE: a bundle proves LOG integrity (inclusion, checkpoint signature/consistency), "
                "never a Rust-producer capsule's own detached signed-statement "
                "(signed-statements/<capsule_id>.cose is not carried in this artifact)."
            )
        lines.extend(_history_card_lines(bundles, node_id=node_id))
    else:
        lines.append(f"  an artifact of {len(envelope.artifact)} bytes in a form this client does not read")

    if tamper_check:
        flipped = bytes([envelope.artifact[0] ^ 0x01]) + envelope.artifact[1:]
        try:
            dataclasses.replace(envelope, artifact=flipped).verify()
            tampered_ok = True
        except er.VerificationError:
            tampered_ok = False
        lines.append(f"tamper-check (flipped one artifact byte in memory): envelope verifies={tampered_ok} (expected False)")
        if tampered_ok:
            raise AssertionError("tamper-check FAILED to be detected -- the envelope still verifies")
        if bundles:
            tampered = json.loads(json.dumps(body["bundles"][0]))
            tampered["receipt"] = {**tampered["receipt"], "capsule_id": "0" * 64}
            bundle_ok, _errors = verify_bundle(Bundle.from_dict(tampered))
            lines.append(f"tamper-check (flipped receipt.capsule_id in memory): verify.ok={bundle_ok} (expected False)")
            if bundle_ok:
                raise AssertionError("tamper-check FAILED to be detected -- verify_bundle did not flip")

    return "\n".join(lines)


def _subject_from_args(args: argparse.Namespace) -> er.Subject:
    if args.subject == "record":
        return er.Subject("record", args.capsule_id)
    if args.subject == "range":
        return er.Subject("range", tuple(args.range))
    if args.subject == "correlation":
        return er.Subject("correlation", args.correlation)
    return er.Subject(args.subject)


def _freshness(value: str) -> int | str:
    return int(value) if value.isdigit() else value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "peer",
        help="peer's evidence_server.py base URL (default) or, with --via mesh, the peer's hex mesh peer id",
    )
    parser.add_argument(
        "--subject",
        choices=["record", "range", "correlation", "full_history", "checkpoints", "references"],
        default="full_history",
    )
    parser.add_argument("--capsule-id", default=None, help="required for --subject record")
    parser.add_argument(
        "--range", nargs=2, type=int, metavar=("A", "B"), default=None,
        help="required for --subject range: 0-based leaf positions A..B inclusive",
    )
    parser.add_argument("--correlation", default=None, help="required for --subject correlation")
    parser.add_argument(
        "--x-node-id",
        default=None,
        help="required for --subject references: X's stable identity (peer is X's own evidence door)",
    )
    parser.add_argument(
        "--x-range", nargs=2, type=int, metavar=("A", "B"), default=None,
        help="--subject references only: which of X's records to pull (default: all of them)",
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
    coverage = parser.add_mutually_exclusive_group()
    coverage.add_argument("--expected-pin", default=None, help="the anchor digest to be served under")
    coverage.add_argument(
        "--min-freshness", type=_freshness, default=None,
        help="a log size or an RFC 3339 UTC time the anchor must meet (default 0: the freshest held)",
    )
    parser.add_argument("--derivation", default=None, help="e.g. served_summary/1 (needs --expected-pin)")
    parser.add_argument("--nonce", default=None)
    parser.add_argument("--responder-key", default=None, help="the responder's Ed25519 key (hex) to require")
    parser.add_argument("--node-id", default="requester", help="label only, for the rendered history card")
    parser.add_argument(
        "--tamper-check", action="store_true", help="prove a corrupted COPY of the response fails verify"
    )
    parser.add_argument(
        "--via",
        choices=["http", "mesh"],
        default="http",
        help="http (default): POST peer directly. mesh: carry the request over THIS node's own "
        "Mesh-LLM plugin's evidence-request/1 channel (for peers with no reachable HTTP door).",
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
    args = parser.parse_args(argv)

    if args.subject == "record" and not args.capsule_id:
        parser.error("--subject record requires --capsule-id")
    if args.subject == "range" and args.range is None:
        parser.error("--subject range requires --range A B")
    if args.subject == "correlation" and not args.correlation:
        parser.error("--subject correlation requires --correlation")
    if args.subject == "references" and not (args.x_node_id and args.peer_map):
        parser.error("--subject references requires --x-node-id and --peer-map")

    if args.subject == "references":
        with open(args.peer_map, encoding="utf-8") as fh:
            peer_map = json.load(fh)
        try:
            result = run_references(
                args.peer,
                x_node_id=args.x_node_id,
                x_range=tuple(args.x_range) if args.x_range else None,
                peer_map=peer_map,
                k=args.k,
                via=args.via,
                local_host_api=args.local_host_api,
                local_plugin_name=args.local_plugin_name,
            )
        except (RuntimeError, TypeError, ValueError, urllib.error.URLError) as exc:
            print(f"references {args.x_node_id!r} via {args.peer} (via {args.via}) failed: {exc}", file=sys.stderr)
            return 1
        print(render_references_result(result))
        return 0

    request_map = build_request(
        _subject_from_args(args),
        expected_pin=args.expected_pin,
        min_freshness=args.min_freshness,
        derivation=args.derivation,
        nonce=args.nonce,
    )
    post = _post_for(args.peer, via=args.via, local_host_api=args.local_host_api, local_plugin_name=args.local_plugin_name)
    try:
        exchange = post(request_map)
    except (TypeError, ValueError, urllib.error.URLError) as exc:
        print(f"request to {args.peer} (via {args.via}) failed: {exc}", file=sys.stderr)
        return 1

    reply = read_reply(exchange, responder_key=args.responder_key)
    if reply.refusal is not None:
        print(render_refusal(reply))
    elif reply.envelope is not None:
        print(render_artifact(reply, node_id=args.node_id, tamper_check=args.tamper_check))
    else:
        print(f"UNREADABLE REPLY: {'; '.join(reply.errors)}")
        return 1
    return 0 if reply.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
