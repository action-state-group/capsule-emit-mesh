# SPDX-License-Identifier: Apache-2.0
"""This node's responder for ``draft-mih-agent-evidence-request-00``.

The protocol (parsing a request, exact resolution against the anchors held,
signed refusals and the interop profile's artifact envelope, §6.2) is
``agent_action_capsule.evidence_request``'s. This module is the store side:
:class:`MeshEvidenceStore` answers that module's ``EvidenceStore`` questions
from one node's ledger directory (a ``cll.ledger.store.LedgerStore`` or a
flat ``capsules.jsonl``, with the sibling ``checkpoints.jsonl``) and builds
the artifact; :func:`handle_evidence_request` runs ``answer()`` and signs
the envelope with the node key every capsule on this ledger is sealed with
(``state.signing_key_path``), so a refusal, an envelope and a capsule from
one node verify under one identity.

**Anchors.** Each checkpoint in ``checkpoints.jsonl`` carrying its COSE
statement (``checkpoint_cose``) is an anchor, identified by the SHA-256 of
that statement, as the evidencebook responders identify theirs. A
requester pins one with ``coverage.expected_pin``, or asks for
``min_freshness`` (a log size or a time) and gets the freshest that meets
it. A checkpoint without a statement is no anchor.

**Subjects.** A record is named by its ``capsule_id``, the digest its MMR
leaf commits. ``range`` is ``[a, b]`` over 0-based leaf positions.
``correlation`` matches a record carrying the identifier under any
correlator key a mesh producer uses (a nonce, an exchange id, a
counterparty reference, or an adjudication verdict ``contradicted:<id>``).
Mesh records cite no exchange halves by digest, so ``exchange`` is never
held. Matching is exact throughout: no prefixes.

**Artifacts.** The artifact octets are RFC 8785 JSON, the same for every
requester (-00 §5):

* ``record``, ``range``, ``correlation``, ``full_history``: ``{anchor,
  evidence_stream, subject, bundles}``, one ``cll.checkpoint.bundle.Bundle``
  per record in log order, each proving its record's inclusion under the
  anchor checkpoint itself (and that checkpoint's consistency with its
  predecessor). A requester checks each with ``capsule_emit.bundle
  .verify_bundle`` and that its ``checkpoint_cose`` hashes to the anchor.
  Only records the anchor covers are served; more than
  :data:`MAX_ANSWER_RECORDS` is refused ``policy_declined`` (ask for a
  range). There is no paging: an answer is whole or refused.
* ``checkpoints``: ``{anchor, checkpoints, evidence_stream, subject}``, the
  ``checkpoints.jsonl`` lines up to the anchor (each with its witnesses and
  COSE statement). This replaces the pre-00 ``chain_segment`` subject.
* ``served_summary/1`` (a mesh derivation, for ``full_history``):
  ``{anchor, derivation, evidence_stream, served_summary, subject}``. It is
  a static export: served only under an ``expected_pin`` naming the latest
  anchor, never on demand.

The envelope carries no verification material: the profile defines
Checkpointed Local Log material only for an artifact that is the committed
entry itself (§6.2.1), and these artifacts carry their proofs inside.

**Additive wire vocabulary** (``[mesh-fabric-vocab-alignment]``).
:func:`augment_evidence_answer_dict` adds the fabric's ``status`` (and, on
an envelope, ``coverage_descriptor``) beside the signed members at
serialization time only. Neither is signed, and a profile reader ignores
both: an envelope is ``SATISFIED``; ``no_such_subject`` is ``NOT_FOUND``,
``coverage_unsatisfiable`` ``NOT_COMMITTED`` and ``policy_declined``
``WITHHELD``; any other reason stays a bare refusal.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Collection, Iterator, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent_action_capsule import evidence_request as er
from agent_action_capsule.canonical import jcs

#: The mesh derivation this responder serves besides plain subjects.
SERVED_SUMMARY_DERIVATION_TOKEN = "served_summary/1"

#: The most records one answer carries; a larger subject is refused
#: ``policy_declined``.
MAX_ANSWER_RECORDS = 200

#: The most checkpoints one ``checkpoints`` answer carries.
MAX_ANSWER_CHECKPOINTS = 1024

#: [mesh-fabric-vocab-alignment] the fabric's additive per-answer status
#: vocabulary -- see the module docstring.
STATUS_SATISFIED = "SATISFIED"
STATUS_NOT_FOUND = "NOT_FOUND"
STATUS_WITHHELD = "WITHHELD"
STATUS_NOT_COMMITTED = "NOT_COMMITTED"

_STATUS_BY_REFUSAL_REASON: dict[str, str] = {
    er.REASON_NO_SUCH_SUBJECT: STATUS_NOT_FOUND,
    er.REASON_COVERAGE_UNSATISFIABLE: STATUS_NOT_COMMITTED,
    er.REASON_POLICY_DECLINED: STATUS_WITHHELD,
}


def status_for_refusal_reason(reason: str) -> str | None:
    """The additive ``status`` for a signed refusal's ``reason``, or ``None``
    when the reason stays a bare refusal reason (``request_malformed`` and
    anything this mapping does not name -- never guessed)."""
    return _STATUS_BY_REFUSAL_REASON.get(reason)


#: [mesh-fabric-vocab-alignment] the fabric's ``coverage_descriptor``
#: vocabulary. See :func:`coverage_descriptor_for` for which of these this
#: responder is ever entitled to claim.
COVERAGE_DESCRIPTOR_RECORD_INCLUSION = "record_inclusion"
COVERAGE_DESCRIPTOR_RANGE_COMPLETENESS = "range_completeness"
COVERAGE_DESCRIPTOR_CAPTURE_COVERAGE = "capture_coverage"
COVERAGE_DESCRIPTOR_RECONCILIATION_COVERAGE = "reconciliation_coverage"
COVERAGE_DESCRIPTOR_CORROBORATION = "corroboration"
ALL_COVERAGE_DESCRIPTORS = frozenset(
    {
        COVERAGE_DESCRIPTOR_RECORD_INCLUSION,
        COVERAGE_DESCRIPTOR_RANGE_COMPLETENESS,
        COVERAGE_DESCRIPTOR_CAPTURE_COVERAGE,
        COVERAGE_DESCRIPTOR_RECONCILIATION_COVERAGE,
        COVERAGE_DESCRIPTOR_CORROBORATION,
    }
)
#: Descriptors a unilateral, single-ledger answer can never establish: each
#: needs a second party's ledger (``capture_coverage``,
#: ``reconciliation_coverage``) or a third party's judgment
#: (``corroboration``).
_BILATERAL_ONLY_COVERAGE_DESCRIPTORS = frozenset(
    {
        COVERAGE_DESCRIPTOR_CAPTURE_COVERAGE,
        COVERAGE_DESCRIPTOR_RECONCILIATION_COVERAGE,
        COVERAGE_DESCRIPTOR_CORROBORATION,
    }
)

#: Subject forms whose artifact is a set of records: an answer is whole or
#: refused, so it establishes the selection's completeness.
_RECORD_SET_FORMS = frozenset({"range", "correlation", "full_history"})


def coverage_descriptor_for(subject_form: str, *, is_final_page: bool = True) -> list[str] | None:
    """Which ``ALL_COVERAGE_DESCRIPTORS`` an answer for ``subject_form``
    establishes, never more than it does. A record answer proves log
    inclusion; a record-set answer (or the final page of a paged one, for
    the redress door's ``bundles`` answers) also that the whole selection was
    returned. ``checkpoints`` carries no records, so it gets none
    (``None``); neither does any form this function does not reason
    about."""
    if subject_form == "record":
        return [COVERAGE_DESCRIPTOR_RECORD_INCLUSION]
    if subject_form in _RECORD_SET_FORMS:
        establishes = [COVERAGE_DESCRIPTOR_RECORD_INCLUSION]
        if is_final_page:
            establishes.append(COVERAGE_DESCRIPTOR_RANGE_COMPLETENESS)
        return establishes
    return None


def _validate_coverage_descriptor(subject_form: str, establishes: list[str]) -> None:
    """Raise rather than ship a bilateral claim from a unilateral answer."""
    claimed = _BILATERAL_ONLY_COVERAGE_DESCRIPTORS.intersection(establishes)
    if claimed:
        raise ValueError(
            f"coverage_descriptor for subject {subject_form!r} claims {sorted(claimed)} -- "
            "a unilateral, single-ledger answer can never establish bilateral coverage"
        )


#: [mesh-fabric-vocab-alignment] the fabric's request ``purpose`` vocabulary.
PURPOSE_COUNTERPARTY_CHECK = "counterparty_check"
PURPOSE_STRANGER_SELECTION = "stranger_selection"
PURPOSE_ADJUDICATION = "adjudication"
PURPOSE_RECONCILIATION = "reconciliation"
REQUEST_PURPOSES = frozenset(
    {PURPOSE_COUNTERPARTY_CHECK, PURPOSE_STRANGER_SELECTION, PURPOSE_ADJUDICATION, PURPOSE_RECONCILIATION}
)


def log_request_purpose(request_bytes: bytes) -> None:
    """Log the optional ``purpose``/``contract_ref`` members of a request.

    -00 ignores members it does not define (§3), so these never reach
    resolution: two requests that differ only in ``purpose`` get the same
    artifact. An unrecognized ``purpose`` is logged as is, never refused."""
    try:
        data = json.loads(request_bytes)
    except Exception:
        # A request that is not JSON is refused request_malformed by answer().
        return
    if not isinstance(data, dict):
        return
    purpose = data.get("purpose")
    contract_ref = data.get("contract_ref")
    if purpose is None and contract_ref is None:
        return
    unrecognized = "" if purpose is None or purpose in REQUEST_PURPOSES else " (unrecognized purpose)"
    print(f"[mesh-fabric-vocab-alignment] evidence-request purpose={purpose!r} contract_ref={contract_ref!r}{unrecognized}")


def augment_evidence_answer_dict(d: dict[str, Any]) -> dict[str, Any]:
    """Add the fabric's ``status`` (and ``coverage_descriptor``) to a reply's
    wire dict, never changing an existing member and never mutating ``d``.

    An envelope (``artifact_digest``) is ``SATISFIED``; a refusal
    (``reason``) maps by :func:`status_for_refusal_reason`. The redress
    door's ``bundles`` answers (``moderation_evidence_door``) are not
    evidence-request envelopes; for them ``coverage_descriptor`` goes on
    each bundle, as before."""
    out = dict(d)
    if "artifact_digest" in out:
        out["status"] = STATUS_SATISFIED
        subject = out.get("subject")
        form = next(iter(subject)) if isinstance(subject, dict) and len(subject) == 1 else ""
        establishes = None if out.get("derivation") else coverage_descriptor_for(form)
        if establishes is not None:
            _validate_coverage_descriptor(form, establishes)
            out["coverage_descriptor"] = establishes
    elif "bundles" in out:
        out["status"] = STATUS_SATISFIED
        form = out.get("subject_kind", "")
        establishes = coverage_descriptor_for(
            "record" if form not in _RECORD_SET_FORMS else form, is_final_page=out.get("next_page_token") is None
        )
        if establishes is not None:
            _validate_coverage_descriptor(form, establishes)
            out["bundles"] = [{**b, "coverage_descriptor": establishes} for b in out["bundles"]]
    elif "reason" in out:
        status = status_for_refusal_reason(out["reason"])
        if status is not None:
            out["status"] = status
    return out


# --- the store -----------------------------------------------------------------

#: Keys a mesh producer nests a correlator under (free-form
#: ``compute_attestation`` extension data, so found at any depth).
CORRELATION_KEYS = frozenset({"nonce", "client_nonce", "exchange_id", "counterparty_ref"})


def _values_under(obj: Any, keys: frozenset[str]) -> Iterator[Any]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in keys:
                yield v
            yield from _values_under(v, keys)
    elif isinstance(obj, list):
        for item in obj:
            yield from _values_under(item, keys)


def carries_correlation(record: dict[str, Any], correlation_id: str) -> bool:
    """True when ``record`` carries ``correlation_id`` exactly, under a
    correlator key or as the owner an adjudication verdict contradicts."""
    if any(v == correlation_id for v in _values_under(record, CORRELATION_KEYS)):
        return True
    return any(
        isinstance(block, dict) and block.get("verdict") == f"contradicted:{correlation_id}"
        for block in _values_under(record, frozenset({"adjudication"}))
    )


def _read_checkpoint_lines(ledger_dir: Path) -> list[dict[str, Any]]:
    path = ledger_dir / "checkpoints.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


@dataclass(frozen=True)
class _Checkpoint:
    line: dict[str, Any]
    record: Any  # cll.checkpoint.CheckpointRecord
    anchor: er.Anchor


class MeshEvidenceStore:
    """``agent_action_capsule.evidence_request.EvidenceStore`` over one
    node's ledger directory, read once when constructed (one per request,
    so an answer is a function of the ledger as it stood)."""

    def __init__(self, ledger_dir: Path):
        from cll.checkpoint.emit import CheckpointRecord
        from cll.checkpoint.core import leaf_count

        from ledger_store_backend import as_ledger_dir, read_all_capsules

        self.ledger_dir = as_ledger_dir(Path(ledger_dir))
        self.records, _archived = read_all_capsules(self.ledger_dir)
        self.index_of: dict[str, int] = {}
        for i, record in enumerate(self.records):
            self.index_of.setdefault(record.get("capsule_id"), i)
        self.checkpoints: list[_Checkpoint] = []
        for line in _read_checkpoint_lines(self.ledger_dir):
            cose_hex = line.get("checkpoint_cose")
            if not cose_hex:
                continue
            record = CheckpointRecord.from_dict({k: v for k, v in line.items() if k != "checkpoint_cose"})
            anchor = er.Anchor(
                digest=hashlib.sha256(bytes.fromhex(cose_hex)).hexdigest(),
                size=leaf_count(record.mmr_size),
                issued_at=record.timestamp,
            )
            self.checkpoints.append(_Checkpoint(line, record, anchor))

    # -- the EvidenceStore questions --

    def holds_record(self, digest: str) -> bool:
        return digest in self.index_of

    def holds_correlation(self, correlation_id: str) -> bool:
        return any(carries_correlation(r, correlation_id) for r in self.records)

    def cites_exchange(self, half_digest: str) -> bool:
        return False

    def positional_ordering(self) -> bool:
        return True

    def anchors(self) -> Sequence[er.Anchor]:
        return [cp.anchor for cp in self.checkpoints]

    def derivation_forms(self, derivation: str) -> Collection[str] | None:
        if derivation == SERVED_SUMMARY_DERIVATION_TOKEN:
            return {"full_history"}
        return None

    def force_checkpoint(self, signer: Any) -> None:
        # answer() calls this only with allow_forced_checkpoint=True, which
        # handle_evidence_request never passes: this door never writes.
        raise NotImplementedError("this responder never checkpoints in response to a read")

    def artifact(self, subject: er.Subject, derivation: str | None, resolution: er.Resolution) -> bytes:
        at = self._checkpoint_for(resolution.anchor)
        head = {"anchor": at.anchor.digest, "evidence_stream": at.record.log_id, "subject": subject.to_wire()}
        if derivation == SERVED_SUMMARY_DERIVATION_TOKEN:
            return jcs({**head, "derivation": derivation, "served_summary": self._served_summary(at)})
        if subject.form == "checkpoints":
            chain = self.checkpoints[: self.checkpoints.index(at) + 1]
            if len(chain) > MAX_ANSWER_CHECKPOINTS:
                raise er.Decline(er.REASON_POLICY_DECLINED, "more checkpoints than one answer carries")
            return jcs({**head, "checkpoints": [cp.line for cp in chain]})
        indices = self._record_indices(subject, at.anchor.size)
        if len(indices) > MAX_ANSWER_RECORDS:
            raise er.Decline(er.REASON_POLICY_DECLINED, f"more than {MAX_ANSWER_RECORDS} records: ask for a range")
        return jcs({**head, "bundles": [b.to_dict() for b in self._bundles(indices, at)]})

    # -- building --

    def _checkpoint_for(self, anchor: er.Anchor | None) -> _Checkpoint:
        found = next((cp for cp in self.checkpoints if anchor is not None and cp.anchor == anchor), None)
        if found is None:
            # resolve() resolves only to anchors() or to an exchange half,
            # and this store holds no exchange subjects.
            raise er.Decline(er.REASON_COVERAGE_UNSATISFIABLE, "no anchor to serve under")
        return found

    def _record_indices(self, subject: er.Subject, covered: int) -> list[int]:
        if subject.form == "record":
            index = self.index_of[subject.content]
            if index >= covered:
                raise er.Decline(er.REASON_COVERAGE_UNSATISFIABLE, "the record is not under the anchor yet")
            return [index]
        if subject.form == "range":
            a, b = subject.content
            return list(range(a, b + 1))
        if subject.form == "correlation":
            indices = [i for i, r in enumerate(self.records[:covered]) if carries_correlation(r, subject.content)]
            if not indices:
                raise er.Decline(er.REASON_COVERAGE_UNSATISFIABLE, "no record carrying it is under the anchor yet")
            return indices
        return list(range(min(covered, len(self.records))))  # full_history

    def _bundles(self, indices: list[int], at: _Checkpoint) -> list[Any]:
        """One bundle per record at ``indices``, each under ``at`` itself:
        ``cll.checkpoint.bundle.bundle`` proves a record under the first
        checkpoint covering it, and -00 serves under the resolved anchor."""
        from cll.checkpoint.bundle import Bundle
        from cll.checkpoint import core as mmr_core
        from cll.checkpoint.store import MemoryNodeStore

        cp = at.record
        covered = at.anchor.size
        if len(self.records) < covered:
            # Records under the anchor are archived (an unmounted segment):
            # nothing can be proven until they are mounted again.
            raise er.Decline(er.REASON_COVERAGE_UNSATISFIABLE, "records under the anchor are not mounted")
        prior = None
        if cp.prev_size > 0:
            prior = next((c.record for c in self.checkpoints if c.record.mmr_size == cp.prev_size), None)
            if prior is None:
                raise er.Decline(er.REASON_COVERAGE_UNSATISFIABLE, "the anchor's predecessor checkpoint is missing")
        store = MemoryNodeStore()
        for record in self.records[:covered]:
            mmr_core.add_leaf(store, mmr_core.leaf_hash(bytes.fromhex(record["capsule_id"])))
        if store.size() != cp.mmr_size:
            raise er.Decline(er.REASON_COVERAGE_UNSATISFIABLE, "the ledger does not reproduce the anchor")
        consistency = mmr_core.consistency_proof(store, prior.mmr_size, cp.mmr_size) if prior is not None else None
        return [
            Bundle(
                v=1,
                capsule_id=self.records[i]["capsule_id"],
                seq=i + 1,
                receipt=self.records[i],
                inclusion_proof=mmr_core.inclusion_proof(store, i, cp.mmr_size),
                checkpoint=cp,
                prior_checkpoint=prior,
                consistency_proof=consistency,
                checkpoint_cose=bytes.fromhex(at.line["checkpoint_cose"]),
            )
            for i in indices
        ]

    def _served_summary(self, at: _Checkpoint) -> dict[str, Any]:
        from served_summary import answer_served_summary_request

        lines = [cp.line for cp in self.checkpoints]
        result = answer_served_summary_request(
            capsule_records=self.records,
            checkpoint_lines=lines,
            expected_pin=at.record.root,
        )
        if result["status"] != "ok":
            raise er.Decline(er.REASON_COVERAGE_UNSATISFIABLE, result.get("reason", ""))
        return result["served_summary"]


# --- answering -------------------------------------------------------------------


def _profile_time(value: str) -> str:
    """``YYYY-MM-DDTHH:MM:SSZ`` (profile §5.2) for an RFC 3339 UTC time,
    dropping any fraction: never later than ``value``."""
    seconds, _nanos = er.parse_utc(value)
    return datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _now_profile_time() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def node_signer(state: Any) -> Any:
    """The node key ``state`` seals its capsules with, as a signer whose
    ``sign(body)`` returns ``(sig_hex, key_id)``."""
    import os

    from capsule_emit.signing import resolve_signer

    return resolve_signer(os.fspath(state.ledger_dir), key_path=state.signing_key_path)


def handle_evidence_request(state: Any, request_bytes: bytes, *, now: str | None = None) -> er.Envelope | er.Refusal:
    """Answer one evidence request (its JSON bytes as received) against
    ``state``'s own ledger: a signed :class:`~agent_action_capsule
    .evidence_request.Envelope` or a signed ``Refusal``. Never raises for any
    request bytes.

    ``now`` (RFC 3339 UTC) overrides the clock for deterministic tests; the
    envelope's ``issued_at`` is it to the second. The door never writes:
    ``allow_forced_checkpoint`` stays off, so ``min_freshness`` is answered
    from the anchors already held.
    """
    log_request_purpose(request_bytes)
    issued_at = _profile_time(now) if now is not None else _now_profile_time()
    signer = node_signer(state)

    try:
        request = er.parse_request(request_bytes)
    except er.RequestError:
        request = None
    if (
        request is not None
        and request.derivation == SERVED_SUMMARY_DERIVATION_TOKEN
        and request.coverage.expected_pin is None
    ):
        # A static export: never built on demand for whatever is freshest.
        return er.sign_refusal(
            er.request_digest(request_bytes), er.REASON_POLICY_DECLINED, signer=signer, issued_at=issued_at
        )

    store = MeshEvidenceStore(state.ledger_dir)
    result = er.answer(request_bytes, store=store, signer=signer, now=issued_at)
    if isinstance(result, er.Refusal):
        return result

    freshness = None
    min_freshness = request.coverage.min_freshness
    if min_freshness is not None:
        anchor = next(a for a in store.anchors() if a.digest == result.anchor)
        freshness = anchor.size if isinstance(min_freshness, int) else _profile_time(anchor.issued_at)
    return er.sign_envelope(
        request_bytes,
        result.subject,
        result.anchor,
        result.body,
        signer=signer,
        issued_at=issued_at,
        derivation=result.derivation,
        freshness=freshness,
    )


def reply_to_wire(reply: er.Envelope | er.Refusal) -> dict[str, Any]:
    """A reply in the JSON binding, as a dict, with the additive vocabulary
    of :func:`augment_evidence_answer_dict`."""
    if isinstance(reply, er.Envelope):
        d = json.loads(reply.encode("json"))
    else:
        d = reply.to_dict()
    return augment_evidence_answer_dict(d)
