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

Artifacts are read in the forms evidencebook, the Mesh-LLM capsules plugin
and this repo's door (``evidence_responder.py``) serve, and each is checked
the way the plugin's requester checks it:

  * ``record``: the record's ledger line, whose recomputed ``capsule_id`` is
    the subject (or the ``capsule_id`` preimage itself, which the profile's
    ``anchor_inclusion`` proves); the material is the anchor checkpoint, the
    record's inclusion proof and, when the anchor extends an earlier
    checkpoint, its consistency proof;
  * ``range``, ``correlation``, ``full_history``: ``{anchor,
    evidence_stream, records, subject}``, each record ``{body, digest,
    leaf_index}``, its body the record its digest names, in log order and
    under the anchor; the material is the anchor checkpoint and one
    inclusion proof per record;
  * ``checkpoints``: every checkpoint's COSE statement in hex, starting the
    stream, each extending the one before it, the last the anchor.

Every checkpoint statement must verify under the responder's own key and the
anchor's must hash to the envelope's anchor. A record proven this way is
proven in the LOG (inclusion under a checkpoint the responder signed); its
producer's own signature is a separate question, which the rendering
leaves open. Witness receipts ride beside the envelope (``witness_receipts``)
and each counts only for the checkpoint it is bound to.

Also renders a small "history card" -- ``continuity``/``history_depth``/
``unforked`` -- folded from a ``checkpoints`` answer's statements via
``history_card.build_history_card``.

Usage:
    python3 ask_history.py <peer-base-url> --subject record --capsule-id <cid>
    python3 ask_history.py <peer-base-url> --subject range --range <a> <b>
    python3 ask_history.py <peer-base-url> --subject full_history | checkpoints
    python3 ask_history.py <peer-base-url> --subject correlation --correlation <id>

Coverage is exactly one of ``--expected-pin <anchor digest>`` (the SHA-256 of
a checkpoint's COSE statement) and ``--min-freshness <size or RFC 3339 UTC
time>``; the default is ``--min-freshness 0``, the freshest anchor held.
``--tamper-check`` proves the negative end to end: it flips one byte of the
artifact and the first served record's ``capsule_id`` in memory (never
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
``--x-range`` names which of ``X``'s records to pull (when omitted, its last
:data:`DEFAULT_PULL_RECORDS`, under its freshest anchor: a door serves at most
that many records in one answer); ``--peer-map`` is a local JSON ``{node_id:
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
(4) verify every reply and every returned record OFFLINE before trusting
anything in it -- an unverified record contributes to nothing; (5) fold
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
from capsule_emit.canonicalization import compute_capsule_id
from capsule_emit.checkpoint import StampVerdict, verify_witness_stamp_tristate
from cll.checkpoint.emit import CheckpointRecord, WitnessRecord

from evidence_responder import KIND_CHECKPOINT, KIND_CONSISTENCY, KIND_INCLUSION, WITNESS_RECEIPTS
from history_card import build_history_card, with_references
from sequence_counter import verify_pair_continuity
from witness_pin import default_witness_pin

__all__ = [
    "DEFAULT_REFERENCE_K",
    "Exchange",
    "ReferencesResult",
    "Reply",
    "ServedCheckpoint",
    "ServedRecord",
    "WitnessedSeed",
    "answer_checkpoints",
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
    "served_records",
    "verified_records",
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

#: How many of X's most recent records `references` pulls when no range is
#: given: the most a Mesh door serves in one answer
#: (``evidence_responder.MAX_ANSWER_RECORDS``).
DEFAULT_PULL_RECORDS = 200


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
    the request bytes as sent (-00 §4.2), ``reply`` the reply's octets in the
    JSON binding, as carried (never re-serialized, so a duplicate member
    stays visible to :func:`read_reply`)."""

    request_digest: str
    reply: bytes


#: A transport: sends a request map and returns the :class:`Exchange`.
Post = Callable[[dict[str, Any]], Exchange]


def post_evidence_request(peer_base_url: str, request_map: dict[str, Any], *, timeout: float = 30) -> Exchange:
    """POST ``request_map`` to ``<peer_base_url>/evidence-request``."""
    body = json.dumps(request_map, separators=(",", ":")).encode("utf-8")
    url = peer_base_url.rstrip("/") + "/evidence-request"
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return Exchange(er.request_digest(body), resp.read())


def _no_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"a duplicate member {key!r}")
        out[key] = value
    return out


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
        raw = resp.read()
    result = json.loads(raw, object_pairs_hook=_no_duplicate_members)
    if not isinstance(result, dict):
        raise TypeError("the mesh carrier's answer is not a JSON object")
    if isinstance(result.get("answer"), dict) and er.is_digest(result.get("request_digest")):
        # The plugin already decoded the peer's reply into its own answer:
        # these are its octets, re-encoded.
        return Exchange(result["request_digest"], json.dumps(result["answer"]).encode("utf-8"))
    sent = json.dumps(request_map, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return Exchange(er.request_digest(sent), raw)


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
    #: The reply's unsigned ``witness_receipts``: ``(checkpoint digest,
    #: WitnessRecord)`` pairs, each bound to nothing yet (see
    #: :func:`served_records` and :func:`answer_checkpoints`).
    witness_receipts: tuple[tuple[str, WitnessRecord], ...] = ()


def _witness_receipts(raw: bytes) -> tuple[tuple[tuple[str, WitnessRecord], ...], list[str]]:
    """The reply's ``witness_receipts`` member, read from the octets as
    carried. A member that is present but malformed is an error, as at the
    plugin's requester."""
    try:
        members = json.loads(raw)
    except (UnicodeDecodeError, ValueError):
        return (), []
    carried = members.get(WITNESS_RECEIPTS) if isinstance(members, dict) else None
    if carried is None:
        return (), []
    if not isinstance(carried, list):
        return (), ["witness_receipts is not a list"]
    out: list[tuple[str, WitnessRecord]] = []
    for item in carried:
        try:
            digest = item["checkpoint"]
            if not er.is_digest(digest):
                raise ValueError(digest)
            out.append((digest, WitnessRecord.from_dict(item["witness"])))
        except (KeyError, TypeError, ValueError, AttributeError):
            return (), ["a witness receipt is malformed"]
    return tuple(out), []


def read_reply(exchange: Exchange, *, responder_key: str | None = None, trust: TrustPolicy | None = None) -> Reply:
    """Read and check a reply offline (see the module docstring). Never
    raises for any reply."""
    errors: list[str] = []
    try:
        parsed = er.parse_reply(exchange.reply, "json")
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
        cll = er.check_cll_material(envelope, trust or _responder_log_trust(envelope))
        if cll.status == FAIL:
            errors.append(f"anchor inclusion fails: {cll.detail}")
    receipts, receipt_errors = _witness_receipts(exchange.reply)
    errors.extend(receipt_errors)
    try:
        body = json.loads(envelope.artifact)
    except (UnicodeDecodeError, ValueError):
        body = None
    return Reply(ok=not errors, errors=tuple(errors), envelope=envelope, body=body, cll=cll, witness_receipts=receipts)


class _LogsUnderKey:
    """Every log (any ``iss``/``sub``) whose checkpoints ``kid`` signs: the
    ``log_keys`` of :func:`_responder_log_trust`."""

    def __init__(self, kid: str):
        self.kid = kid

    def __contains__(self, entry: object) -> bool:
        return isinstance(entry, tuple) and len(entry) == 3 and entry[2] == self.kid


def _responder_log_trust(envelope: er.Envelope) -> TrustPolicy:
    """The relying party's log key for the anchor checkpoint when none is
    given: the responder's own, which signs a mesh node's (and the plugin's)
    checkpoints, as the plugin's requester takes it."""
    return TrustPolicy(responder_keys=frozenset({envelope.responder}), log_keys=_LogsUnderKey(envelope.responder))


@dataclass(frozen=True)
class ServedCheckpoint:
    """A checkpoint an answer carries, its statement verified under the
    responder's key: ``record`` is the JSON form it states (no
    ``signature``: the statement's own COSE signature stands for it), with
    the witness receipts the reply carries for it, each bound to it."""

    digest: str
    statement: bytes
    record: CheckpointRecord
    #: The statement's commitment: the MMR's peaks at ``record.mmr_size``.
    peaks: tuple[bytes, ...]
    prev_peaks: tuple[bytes, ...]

    def line(self) -> dict[str, Any]:
        """The ``checkpoints.jsonl`` line this checkpoint is, as
        ``history_card.build_history_card`` reads one."""
        return {**self.record.to_dict(), "checkpoint_cose": self.statement.hex()}


def _served_checkpoint(statement: bytes, reply: Reply) -> ServedCheckpoint | None:
    """``statement`` as a :class:`ServedCheckpoint` when it verifies and is
    signed by the envelope's responder; ``None`` otherwise."""
    from cll.checkpoint.cose_wire import verify_checkpoint_cose_offline

    checked = verify_checkpoint_cose_offline(statement)
    if not checked.ok or checked.decoded is None or checked.decoded.key_id != reply.envelope.responder:
        return None
    digest = hashlib.sha256(statement).hexdigest()
    record = checked.decoded.to_checkpoint_record()
    bound = sha256_hex_of_hex(record.digest())
    record.witnesses = [w for d, w in reply.witness_receipts if d == digest and w.entry_hash == bound]
    return ServedCheckpoint(
        digest=digest,
        statement=statement,
        record=record,
        peaks=tuple(bytes.fromhex(h) if isinstance(h, str) else bytes(h) for h in checked.decoded.new_peak_hashes),
        prev_peaks=tuple(bytes.fromhex(h) if isinstance(h, str) else bytes(h) for h in checked.decoded.prev_peak_hashes),
    )


def sha256_hex_of_hex(digest_hex: str) -> str:
    """A witness receipt's entry hash for a checkpoint digest:
    ``SHA-256(bytes of the digest)``."""
    return hashlib.sha256(bytes.fromhex(digest_hex)).hexdigest()


@dataclass(frozen=True)
class ServedRecord:
    """A record an answer carries, proven under its anchor checkpoint:
    ``receipt`` is the record's ledger line, parsed."""

    leaf_index: int
    capsule_id: str
    receipt: dict[str, Any]


def _record_digest(body: bytes) -> str | None:
    """The digest a record body proves: its recomputed ``capsule_id`` when
    it is a ledger line stating that id, as the plugin's requester reads
    one (capsule-emit's ``compute_capsule_id``, the twin of the one it
    calls, for a format-4 record and an earlier one alike). ``None`` for a
    body that is not such a line."""
    try:
        line = json.loads(body)
        stated = line.get("capsule_id")
        return stated if isinstance(stated, str) and compute_capsule_id(line) == stated else None
    except (UnicodeDecodeError, ValueError, TypeError, AttributeError):
        return None


def _parsed_record(body: bytes) -> dict[str, Any] | None:
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _proves(proof: bytes, leaf: int, entry_hex: str, peaks: tuple[bytes, ...]) -> bool:
    """``proof`` is a ``cll-inclusion-proof`` for zero-based leaf ``leaf``
    and the entry ``entry_hex``, reaching one of ``peaks``."""
    import cbor2

    try:
        index = cbor2.loads(proof)[0]
        er.verify_cll_inclusion(list(peaks), bytes.fromhex(entry_hex), proof)
    except (er.VerificationError, ValueError, TypeError, IndexError, KeyError, cbor2.CBORDecodeError):
        return False
    return index == 2 * leaf - bin(leaf).count("1")


def _material(reply: Reply) -> list[tuple[str, bytes]]:
    return list(reply.envelope.verification)


def served_records(reply: Reply) -> tuple[list[ServedRecord], ServedCheckpoint | None, list[str]]:
    """The records of a ``record``, ``range``, ``correlation`` or
    ``full_history`` answer, the anchor checkpoint they are proven under, and
    the problems that keep them from being trusted (any problem: trust none).
    The checks are the plugin's requester's (see the module docstring)."""
    envelope = reply.envelope
    if envelope is None or envelope.derivation is not None:
        return [], None, ["not a plain record answer"]
    (form,) = envelope.subject.to_wire()
    material = _material(reply)
    if form == "record":
        return _served_record(reply, material)
    if form not in ("range", "correlation", "full_history", "exchange"):
        return [], None, ["not a record answer"]
    body = reply.body if isinstance(reply.body, dict) else {}
    records = body.get("records")
    if not isinstance(records, list) or not records:
        return [], None, ["the artifact carries no records"]
    if body.get("subject") != envelope.subject.to_wire():
        return [], None, ["the artifact is for another subject"]
    if [k for k, _ in material] != [KIND_CHECKPOINT] + [KIND_INCLUSION] * len(records):
        return [], None, ["the material is not the anchor checkpoint and one inclusion proof per record"]
    anchor, problems = _anchor(reply, material[0][1], body)
    if anchor is None:
        return [], None, problems
    covered = _leaf_count(anchor.record.mmr_size)
    out: list[ServedRecord] = []
    for i, (record, (_, proof)) in enumerate(zip(records, material[1:])):
        try:
            raw = bytes.fromhex(record["body"])
            digest, leaf = record["digest"], record["leaf_index"]
        except (KeyError, TypeError, ValueError):
            return [], anchor, [f"record {i} is malformed"]
        if not (er.is_digest(digest) and (hashlib.sha256(raw).hexdigest() == digest or _record_digest(raw) == digest)):
            return [], anchor, [f"record {i}'s body is not the record its digest names"]
        if not (isinstance(leaf, int) and not isinstance(leaf, bool) and 0 <= leaf < covered):
            return [], anchor, [f"record {i} is not under the anchor"]
        if out and out[-1].leaf_index >= leaf:
            return [], anchor, ["the records are not in log order"]
        if not _proves(proof, leaf, digest, anchor.peaks):
            return [], anchor, [f"record {i}'s inclusion proof does not hold"]
        parsed = _parsed_record(raw)
        out.append(ServedRecord(leaf_index=leaf, capsule_id=digest, receipt=parsed if parsed is not None else {}))
    leaves = [r.leaf_index for r in out]
    if form == "range":
        a, b = envelope.subject.content
        if leaves != list(range(a, b + 1)):
            return [], anchor, ["the records are not the range asked for"]
    elif form == "full_history" and leaves != list(range(covered)):
        return [], anchor, ["the records are not the full history under the anchor"]
    return out, anchor, []


def _served_record(reply: Reply, material: list[tuple[str, bytes]]) -> tuple[list[ServedRecord], ServedCheckpoint | None, list[str]]:
    envelope = reply.envelope
    digest = envelope.subject.content
    artifact = envelope.artifact
    if envelope.artifact_digest != digest and _record_digest(artifact) != digest:
        return [], None, ["the artifact is not the record the subject names"]
    kinds = [k for k, _ in material]
    if kinds not in ([KIND_CHECKPOINT, KIND_INCLUSION], [KIND_CHECKPOINT, KIND_INCLUSION, KIND_CONSISTENCY]):
        return [], None, ["the material is not the anchor checkpoint and the record's proofs"]
    anchor, problems = _anchor(reply, material[0][1], None)
    if anchor is None:
        return [], None, problems
    import cbor2

    try:
        index = cbor2.loads(material[1][1])[0]
    except (ValueError, TypeError, IndexError, KeyError, cbor2.CBORDecodeError):
        return [], anchor, ["the inclusion proof is malformed"]
    leaf = _leaf_of_node_index(index)
    if leaf is None or leaf >= _leaf_count(anchor.record.mmr_size) or not _proves(material[1][1], leaf, digest, anchor.peaks):
        return [], anchor, ["the record's inclusion proof does not hold"]
    if len(material) == 3:
        try:
            er.verify_cll_consistency(list(anchor.prev_peaks), list(anchor.peaks), material[2][1])
        except er.VerificationError as exc:
            return [], anchor, [f"the anchor's consistency proof does not hold: {exc}"]
    parsed = _parsed_record(artifact)
    return [ServedRecord(leaf_index=leaf, capsule_id=digest, receipt=parsed if parsed is not None else {})], anchor, []


def _leaf_of_node_index(index: object) -> int | None:
    """The zero-based leaf whose MMR node index is ``index`` (a leaf's is
    ``2n - popcount(n)``), or ``None`` when ``index`` is no leaf's. Since
    ``popcount(n) <= 53`` below 2^53, ``n`` lies within 27 of ``index / 2``."""
    if not isinstance(index, int) or isinstance(index, bool) or not 0 <= index < 1 << 53:
        return None
    return next((n for n in range(index // 2, index // 2 + 28) if 2 * n - bin(n).count("1") == index), None)


def _leaf_count(mmr_size: int) -> int:
    from cll.checkpoint.core import leaf_count

    return leaf_count(mmr_size)


def _anchor(reply: Reply, statement: bytes, body: dict[str, Any] | None) -> tuple[ServedCheckpoint | None, list[str]]:
    """The anchor checkpoint ``statement``, when it is the responder's, the
    envelope's anchor and, for an artifact map ``body``, the anchor and
    stream it names."""
    anchor = _served_checkpoint(statement, reply)
    if anchor is None:
        return None, ["the anchor checkpoint is not the responder's, or does not verify"]
    if anchor.digest != reply.envelope.anchor_digest:
        return None, ["the envelope names another anchor than its checkpoint"]
    if body is not None and (body.get("anchor") != anchor.digest or body.get("evidence_stream") != anchor.record.log_id):
        return None, ["the artifact names another anchor or stream than its checkpoint's"]
    return anchor, []


def answer_checkpoints(reply: Reply) -> tuple[list[dict[str, Any]], list[str]]:
    """The checkpoints of a ``checkpoints`` artifact as ``checkpoints.jsonl``
    lines (``history_card.build_history_card`` folds them; each carries the
    witness receipts the reply carries for it), and the problems that keep
    them from being trusted. Every statement must verify under the
    responder's key; the first starts the stream, each extends the one before
    it, and the last is the envelope's anchor."""
    body = reply.body if isinstance(reply.body, dict) else {}
    statements = body.get("checkpoints")
    if reply.envelope is None or not isinstance(statements, list) or not statements:
        return [], ["the artifact carries no checkpoints"]
    listed: list[ServedCheckpoint] = []
    for i, item in enumerate(statements):
        try:
            cp = _served_checkpoint(bytes.fromhex(item), reply)
        except (TypeError, ValueError):
            cp = None
        if cp is None:
            return [], [f"checkpoint {i} is not the responder's, or does not verify"]
        listed.append(cp)
    problems: list[str] = []
    first = listed[0].record
    if first.prev_size != 0 or first.prev_root:
        problems.append("the checkpoint list does not start the stream")
    for prev, nxt in zip(listed, listed[1:]):
        p, n = prev.record, nxt.record
        if n.prev_size != p.mmr_size or n.prev_root != p.root or n.log_id != p.log_id or n.mmr_size <= p.mmr_size:
            problems.append("a checkpoint does not extend the one listed before it")
            break
    if listed[-1].digest != reply.envelope.anchor_digest:
        problems.append("the last checkpoint is not the envelope's anchor")
    if body.get("anchor") != listed[-1].digest or body.get("evidence_stream") != listed[-1].record.log_id:
        problems.append("the artifact names another anchor or stream than its last checkpoint's")
    return [cp.line() for cp in listed], problems


def verified_records(reply: Reply) -> list[ServedRecord]:
    """The records of a checked reply when every check passes: the reply's
    own and :func:`served_records`'. Empty for anything else."""
    if not reply.ok or reply.envelope is None:
        return []
    records, _anchor_cp, problems = served_records(reply)
    return [] if problems else records


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


def discover_counterparties(records: list[ServedRecord], *, exclude_node_id: str) -> list[str]:
    """From ``X``'s own already-verified records (each ``receipt`` is the
    raw ledger entry -- structural attestation fields only, never a
    disclosed payload), collect every distinct node identity ``X``'s OWN
    records name as a counterparty. Excludes ``X`` itself and the honest
    ``"unknown"`` marker -- never a fabricated candidate. Sorted, so the
    result is a pure function of the record set.
    """
    found: set[str] = set()
    for r in records:
        for v in _iter_values_by_key(r.receipt, _COUNTERPARTY_NAMING_KEYS):
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


def witnessed_seed(checkpoints: list[CheckpointRecord]) -> WitnessedSeed | None:
    """The latest (largest ``mmr_size``) of ``checkpoints`` -- each one an
    answer carries, its statement verified under the responder's key, with
    the receipts carried for it -- whose witness receipt re-verifies as
    :attr:`StampVerdict.WITNESSED`. A receipt is re-verified, never trusted
    for being present, and a producer-set ``is_stub`` flag counts for
    nothing. ``None`` when there is no such checkpoint -- the caller then
    draws no sample."""
    best: WitnessedSeed | None = None
    for cp in checkpoints:
        if best is not None and cp.mmr_size <= best.mmr_size:
            continue
        for w in cp.witnesses or []:
            verdict, _stamp_errors = verify_witness_stamp_tristate(cp, w, ts_pubkey_pem=default_witness_pin(w.ts_url))
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
    #: X's own history card (folded from X's ``checkpoints`` answer, per
    #: ``history_card.build_history_card``), with this result's counts
    #: folded in via ``history_card.with_references``. ``None`` when that
    #: answer could not be had (only possible with an explicit ``x_range``).
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


def _x_checkpoints(post: Post, node_id: str) -> tuple[Reply, list[dict[str, Any]]]:
    """``X``'s checkpoint chain, from a ``checkpoints`` answer (a door serves
    one whatever the log's length), checked by :func:`answer_checkpoints`.
    Raises ``RuntimeError`` when it is a refusal or does not check out."""
    reply = read_reply(post(build_request(er.Subject("checkpoints"))))
    if reply.refusal is not None:
        raise RuntimeError(f"could not read {node_id}'s checkpoints: refused {reply.refusal.reason}")
    lines, problems = answer_checkpoints(reply)
    problems = [*reply.errors, *problems]
    if problems:
        raise RuntimeError(f"{node_id}'s checkpoints answer does not check out: {'; '.join(problems)}")
    return reply, lines


def _recent_records_request(lines: list[dict[str, Any]], node_id: str) -> dict[str, Any]:
    """A request for the last :data:`DEFAULT_PULL_RECORDS` records under the
    latest of ``X``'s checked checkpoint ``lines`` that a witness receipt
    verifies for (else the latest), pinned to it, so the pulled records'
    anchor can seed the sample (:func:`witnessed_seed`). The size is the
    anchor's own verified statement's, so a door cannot move the window."""
    from cll.checkpoint.core import leaf_count

    records = [CheckpointRecord.from_dict(line) for line in lines]
    seeded = witnessed_seed(records)
    at = next((line for line, r in zip(lines, records) if seeded and r.mmr_size == seeded.mmr_size), lines[-1])
    size = leaf_count(at["mmr_size"])
    if size == 0:
        raise RuntimeError(f"{node_id}'s log is empty")
    first = max(0, size - DEFAULT_PULL_RECORDS)
    pin = hashlib.sha256(bytes.fromhex(at["checkpoint_cose"])).hexdigest()
    return build_request(er.Subject("range", (first, size - 1)), expected_pin=pin)


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
    chain: list[dict[str, Any]] = []
    log_id = ""
    try:
        checkpoints_reply, chain = _x_checkpoints(x_post, x_node_id)
        log_id = checkpoints_reply.body.get("evidence_stream", "")
    except RuntimeError:
        if x_range is None:
            raise
    if x_range is not None:
        x_request = build_request(er.Subject("range", x_range))
    else:
        x_request = _recent_records_request(chain, x_node_id)
    x_reply = read_reply(x_post(x_request))
    if x_reply.refusal is not None:
        raise RuntimeError(f"could not pull {x_node_id}'s own records: refused {x_reply.refusal.reason}")
    if not x_reply.ok:
        raise RuntimeError(f"{x_node_id}'s own reply does not check out: {'; '.join(x_reply.errors)}")
    x_records, x_anchor, problems = served_records(x_reply)
    if problems:
        raise RuntimeError(f"{x_node_id}'s own records do not check out: {'; '.join(problems)}")
    verified_x_receipts = [r.receipt for r in x_records]

    candidates = discover_counterparties(x_records, exclude_node_id=x_node_id)
    seed = witnessed_seed([x_anchor.record])
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
        for record in verified_records(read_reply(exchange)):
            _classify_receipt_for_x(record.receipt, x_node_id, tally)

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

    card = None
    if chain:
        card = with_references(
            build_history_card(node_id=x_node_id, log_id=log_id, checkpoint_lines=chain),
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


def render_refusal(reply: Reply) -> str:
    refusal = reply.refusal
    lines = [
        f"REFUSAL reason={refusal.reason} issued_at={refusal.issued_at} key_id={refusal.key_id}",
        f"signed, conformant and answering this request: {reply.ok}",
    ]
    lines.extend(f"    {e}" for e in reply.errors)
    return "\n".join(lines)


def _checkpoints_lines(reply: Reply, *, node_id: str) -> list[str]:
    body = reply.body if isinstance(reply.body, dict) else {}
    lines_in, problems = answer_checkpoints(reply)
    if not lines_in:
        return [f"  {problems[0]}"]
    out = [f"  checkpoints={len(lines_in)}", *(f"    {p}" for p in problems)]
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


def _records_lines(reply: Reply) -> tuple[list[str], list[ServedRecord]]:
    records, anchor, problems = served_records(reply)
    body = reply.body if isinstance(reply.body, dict) else {}
    count = len(body.get("records") or []) if isinstance(body.get("records"), list) else (1 if records else 0)
    out = [f"  records={len(records) if not problems else count}", *(f"    {p}" for p in problems)]
    if anchor is not None:
        out.append(
            f"  anchor checkpoint: log_id={anchor.record.log_id} mmr_size={anchor.record.mmr_size} "
            f"witness receipts bound to it={len(anchor.record.witnesses)}"
        )
    for r in records:
        out.append(f"  record {r.capsule_id} (leaf {r.leaf_index}): proven under the anchor")
    if records:
        out.append(
            "  NOTE: an answer proves LOG integrity (inclusion under a checkpoint the responder signed), "
            "never a Rust-producer capsule's own detached signed-statement "
            "(signed-statements/<capsule_id>.cose is not carried in this artifact)."
        )
    return out, records


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
    records: list[ServedRecord] = []
    if envelope.derivation is not None:
        lines.append(f"  derivation={envelope.derivation} members={sorted(body)}")
    elif form == "checkpoints":
        lines.extend(_checkpoints_lines(reply, node_id=node_id))
    elif form in ("record", "range", "correlation", "full_history", "exchange"):
        record_lines, records = _records_lines(reply)
        lines.extend(record_lines)
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
        if records:
            # The records' checks alone, past the envelope's signature: name
            # another record than the one proven.
            if form == "record":
                forged = dataclasses.replace(envelope, subject=er.Subject("record", "0" * 64))
            else:
                forged_body = json.loads(envelope.artifact)
                forged_body["records"][0]["digest"] = "0" * 64
                forged = dataclasses.replace(envelope, artifact=jcs(forged_body))
            forged_reply = dataclasses.replace(reply, envelope=forged, body=json.loads(forged.artifact))
            still_ok = not served_records(forged_reply)[2]
            lines.append(f"tamper-check (renamed the first record in memory): records check={still_ok} (expected False)")
            if still_ok:
                raise AssertionError("tamper-check FAILED to be detected -- the renamed record still checks")

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
        help="--subject references only: which of X's records to pull (default: its last 200)",
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
