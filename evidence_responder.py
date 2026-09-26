# SPDX-License-Identifier: Apache-2.0
"""Sidecar wiring for E14's evidence-request responder.

The responder's decision logic (request parsing, coverage resolution,
signed refusals, dispatch to ``bundle()``) lives entirely in
``capsule_emit.evidence_request`` — this module is capsule-emit-mesh's
half: it supplies WHICH ledger and WHICH signing key ``answer()`` runs
against for one running sidecar, and nothing else.

``issuer: node_key`` — ``state.signing_key_path`` is the SAME persisted
Ed25519 key (``<keys_dir>/node-key.pem``, ``load_or_create_signing_key``)
every capsule this sidecar already seals is signed with, so a refusal and
a capsule from the same node verify against the same identity.

**Carrier wiring is out of scope here.** This makes the responder
reachable against a real sidecar's ``NodeState`` — not yet reachable over
the wire (the ``HttpBindingManifest`` route / ``evidence-request/1``
subprotocol are separate, later work: E15/E16).

**[mesh-served-summary-derivation] derivation-token dispatch.** The merged
``capsule_emit.evidence_request.answer()`` parses a request's ``derivation``
field but never dispatches on it — it only ever builds ``bundle()``-shaped
answers for ``record``/``range`` subjects. This module is the one place a
derivation TOKEN actually gets answered: a request naming
``derivation: "served_summary/1"`` is intercepted here, BEFORE falling
through to the generic bundle path, and answered from
``served_summary.answer_served_summary_request`` against this same ledger's
checkpoint chain. Any other (or absent) derivation falls through to
``answer()`` unchanged.

**[mesh-fabric-vocab-alignment] additive `status`/`coverage_descriptor`.**
``answer()``'s own ``Artifact``/``Refusal`` objects (and this module's
``Refusal``-shaped served-summary refusal) never change — the fabric's
shared record-header and per-answer status vocabulary convention is layered on ONLY at the
wire-serialization boundary, by ``augment_evidence_answer_dict`` below,
never inside ``handle_evidence_request``'s own return value (so every
existing caller of this module that reads an ``Artifact``/``Refusal``
object directly, rather than its wire JSON, is unaffected). The mapping:
``Artifact`` (an answer WAS satisfied) -> ``status: SATISFIED``;
``reason=no_such_record`` -> ``NOT_FOUND``; ``reason=coverage_unsatisfiable``
-> ``NOT_COMMITTED``; ``reason=policy_decline`` (the delivery door's own
reason, see ``adjudication_delivery.py``) -> ``WITHHELD``;
``reason=request_malformed`` stays a bare refusal reason -- no additive
status, since a request this door could not even parse was never resolved
one way or the other.

**the sharing-policy relationship policy for `record`/`correlation`/
`chain_segment`.** Before today, this door answered every well-formed
request from anyone -- structurally correct (a malformed/absent subject was
always refused), but with no OPERATOR policy at all. ``handle_evidence_request``
now takes two new, both-optional keyword args: ``requester_id`` (a
self-declared identity string the caller supplies out of band -- e.g.
``evidence_server.py``'s ``X-Mesh-Requester-Id`` header; ``None`` when the
caller supplies none) and ``policy`` (a ``share_policy.SharePolicy``; when
``None``, the gate below never runs at all -- see ``share_policy``'s own
"backward-compatible by construction" note). When ``policy`` IS supplied,
every ``record``/``correlation``/``chain_segment`` request is classified by
:func:`classify_relationship` and checked against ``policy.history_segments``
via :func:`relationship_allowed`; a disallowed request is refused
``not_authorized``, signed with this node's own key like every other
refusal here.

Identity here is exactly as self-attested as everything else this system
already trusts a claim about (``counterparty_ref``, ``requesting_party`` --
see ``ask_history.py``'s own ``_COUNTERPARTY_NAMING_KEYS``): this gate is an
operator policy knob (spam/scope reduction), never an access-control
boundary -- a stranger who lies about being a counterparty still cannot
produce a real capsule id or correlation value it has no honest way to
know, and gains nothing a ``peers``-tier operator wouldn't have handed it
anyway. Never a score, never a computed standing -- see ``share_policy``'s
module docstring.

``chain_segment`` is additionally dispatched OUTSIDE ``answer()`` now (see
:func:`_handle_chain_segment_request`), so this module's own
:func:`classify_leaf_kind` -- not ``capsule_emit.chain_segment``'s generic
default -- names a twin-bracketed leaf ``exchange_twin``. Known, honest
scope limit: this path does not (yet) honor ``coverage.min_freshness`` (it
does honor ``coverage.expected_pin``) -- the same class of deliberate
scope-cut as this module's own ``allow_forced_checkpoint`` note above.
"""
from __future__ import annotations

import hashlib
from typing import Any

from capsule_emit.evidence_request import Refusal

from share_policy import SharePolicy

#: The one derivation token this module dispatches on directly. Any other
#: value (including ``None``) falls through to the generic bundle-based
#: ``answer()`` below, unchanged.
SERVED_SUMMARY_DERIVATION_TOKEN = "served_summary/1"

#: [mesh-fabric-vocab-alignment] the fabric's additive per-answer status
#: vocabulary -- see the module docstring.
STATUS_SATISFIED = "SATISFIED"
STATUS_NOT_FOUND = "NOT_FOUND"
STATUS_WITHHELD = "WITHHELD"
STATUS_NOT_COMMITTED = "NOT_COMMITTED"

#: the sharing-policy NEW reason, scoped to this responder's own
#: relationship gate (mirrors `adjudication_delivery.REASON_POLICY_DECLINE`'s
#: precedent of a new reason for a NEW responder decision, not one of E14's
#: own closed `capsule_emit.evidence_request.REFUSAL_REASONS`).
REASON_NOT_AUTHORIZED = "not_authorized"

#: Refusal `reason` -> additive `status`. `request_malformed` is
#: deliberately absent -- see the module docstring.
_STATUS_BY_REFUSAL_REASON: dict[str, str] = {
    "no_such_record": STATUS_NOT_FOUND,
    "coverage_unsatisfiable": STATUS_NOT_COMMITTED,
    "policy_decline": STATUS_WITHHELD,
    REASON_NOT_AUTHORIZED: STATUS_WITHHELD,
}


def status_for_refusal_reason(reason: str) -> str | None:
    """The additive `status` for a signed refusal's `reason`, or `None` when
    *reason* stays a bare refusal reason (`request_malformed`, or anything
    this mapping does not recognize -- never guessed)."""
    return _STATUS_BY_REFUSAL_REASON.get(reason)


#: [mesh-fabric-vocab-alignment] the fabric's `coverage_descriptor` vocabulary
#: -- what a bundle-tier answer can name
#: itself as establishing. See `coverage_descriptor_for`'s docstring for
#: which of these THIS responder is ever entitled to claim.
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
#: Descriptors a UNILATERAL, single-ledger bundle-tier answer can never
#: establish -- each requires a second party's ledger (`capture_coverage`,
#: `reconciliation_coverage`) or a third party's judgment (`corroboration`),
#: none of which this door alone ever has. Reconcile/Close v0
#: (`[mesh-reconcile-and-close-v0]`) and the twin/referee path are the
#: features that will eventually be entitled to claim these -- not this
#: responder.
_BILATERAL_ONLY_COVERAGE_DESCRIPTORS = frozenset(
    {
        COVERAGE_DESCRIPTOR_CAPTURE_COVERAGE,
        COVERAGE_DESCRIPTOR_RECONCILIATION_COVERAGE,
        COVERAGE_DESCRIPTOR_CORROBORATION,
    }
)


def coverage_descriptor_for(subject_kind: str, *, is_final_page: bool) -> list[str] | None:
    """Which `ALL_COVERAGE_DESCRIPTORS` values a bundle-tier answer for
    *subject_kind* establishes -- **never more than it does**. A
    `record`/`range`/`correlation` bundle from this responder proves log
    inclusion, and -- once its own page reaches the end of the resolved
    selection (`is_final_page`) -- that the full selection was returned; it
    never proves bilateral capture completeness, cross-ledger
    reconciliation, or independent corroboration (see
    `_BILATERAL_ONLY_COVERAGE_DESCRIPTORS`). A `chain_segment` subject
    resolves to `capsule_emit.chain_segment.ChainSegment` objects, not
    `Bundle`s (see `_build_chain_segment` in `capsule_emit.evidence_request`)
    -- this responder emits no `coverage_descriptor` for it (`None`,
    absent, never fabricated for a shape this function does not reason
    about)."""
    if subject_kind == "chain_segment":
        return None
    establishes = [COVERAGE_DESCRIPTOR_RECORD_INCLUSION]
    if subject_kind in ("range", "correlation") and is_final_page:
        establishes.append(COVERAGE_DESCRIPTOR_RANGE_COMPLETENESS)
    return establishes


def _validate_coverage_descriptor(subject_kind: str, establishes: list[str]) -> None:
    """Defense in depth for `coverage_descriptor_for`'s own contract: a
    `record`/`range`/`correlation` bundle over ONE node's own ledger is a
    UNILATERAL view. Raises rather than silently stripping a forbidden
    claim, so a future change to `coverage_descriptor_for` that tries to
    assert bilateral coverage fails loudly instead of shipping a false one."""
    claimed = _BILATERAL_ONLY_COVERAGE_DESCRIPTORS.intersection(establishes)
    if claimed:
        raise ValueError(
            f"coverage_descriptor for subject.kind={subject_kind!r} claims {sorted(claimed)} -- "
            "a unilateral, single-ledger bundle-tier answer can never establish bilateral coverage"
        )


#: [mesh-fabric-vocab-alignment] the fabric's request `purpose` vocabulary
#: (see `log_request_purpose`'s docstring for how this responder handles it).
PURPOSE_COUNTERPARTY_CHECK = "counterparty_check"
PURPOSE_STRANGER_SELECTION = "stranger_selection"
PURPOSE_ADJUDICATION = "adjudication"
PURPOSE_RECONCILIATION = "reconciliation"
REQUEST_PURPOSES = frozenset(
    {PURPOSE_COUNTERPARTY_CHECK, PURPOSE_STRANGER_SELECTION, PURPOSE_ADJUDICATION, PURPOSE_RECONCILIATION}
)


def log_request_purpose(request_bytes: bytes) -> None:
    """Read optional `purpose`/`contract_ref` off the raw request JSON, if
    present, and log them -- NEVER parsed into, validated by, or allowed to
    affect `capsule_emit.evidence_request.RequestMap`/`answer()`'s own
    bundle resolution (that module's own `parse_request` already documents
    "unknown fields are ignored, per the draft's shape"; this rides on that
    tolerance rather than changing it). `purpose` is caller-supplied context
    about WHY a request was made (this node's own audit trail), not a
    coverage or subject parameter: two requests identical except for
    `purpose` resolve to byte-identical bundles BY CONSTRUCTION -- this
    function only ever prints, it is never on the path that builds
    `RequestMap`/dispatches to `_build_bundles`. An unrecognized `purpose`
    value is logged as-is and never refused -- the same "unknown fields
    ignored" tolerance, not a new refusal path this module invents."""
    import json as _json

    try:
        data = _json.loads(request_bytes)
    except Exception:
        # Malformed JSON is handled (as request_malformed) by the real
        # parse further down this call's stack -- this function is
        # best-effort logging only, so it declines to log rather than
        # raise or duplicate that decision.
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
    """Additive-only, wire-serialization-time augmentation of an
    `Artifact`/`Refusal`'s own `.to_dict()` output (or this module's plain
    served-summary success dict, left unchanged -- it carries neither
    `bundles` nor `reason`) with the fabric's `status`/`coverage_descriptor`
    vocabulary. Never mutates *d* in place; never changes an EXISTING key's
    value. See the module docstring for the full mapping."""
    out = dict(d)
    if "bundles" in out:
        out["status"] = STATUS_SATISFIED
        is_final_page = out.get("next_page_token") is None
        subject_kind = out.get("subject_kind", "")
        establishes = coverage_descriptor_for(subject_kind, is_final_page=is_final_page)
        if establishes is not None:
            _validate_coverage_descriptor(subject_kind, establishes)
            out["bundles"] = [{**b, "coverage_descriptor": establishes} for b in out["bundles"]]
    elif "reason" in out:
        status = status_for_refusal_reason(out["reason"])
        if status is not None:
            out["status"] = status
    return out


def _sign_refusal(request_digest: str, reason: str, *, signer: Any, issued_at: str) -> Refusal:
    """Sign one ``Refusal`` against an already-resolved ``signer`` --
    ``capsule_emit.evidence_request._refuse`` is private and does exactly
    this three-line stub-then-sign dance; duplicated here rather than
    reached into, same precedent that module's own ``_record_exists`` cites
    for not reaching into a sibling package's private helper. Shared by
    every mesh-local refusal reason this module signs (``served_summary/1``,
    ``not_authorized``, the ``chain_segment`` bypass path)."""
    stub = Refusal(request_digest=request_digest, reason=reason, issued_at=issued_at, key_id="", sig="")
    sig, key_id = signer.sign(stub.signing_body())
    return Refusal(request_digest=request_digest, reason=reason, issued_at=issued_at, key_id=key_id, sig=sig)


def _resolve_state_signer(state: Any) -> Any:
    import os

    from capsule_emit import signing as _signing

    return _signing.resolve_signer(os.fspath(state.ledger_dir), key_path=state.signing_key_path)


def _refuse_served_summary(request_bytes: bytes, reason: str, *, state: Any, issued_at: str) -> Any:
    """Sign a ``served_summary/1`` refusal with the SAME shape and the SAME
    node key every other refusal/capsule from this sidecar carries."""
    request_digest = hashlib.sha256(request_bytes).hexdigest()
    signer = _resolve_state_signer(state)
    return _sign_refusal(request_digest, reason, signer=signer, issued_at=issued_at)


#: the sharing-policy fields a mesh capsule may name a counterparty
#: node under -- the same free-form ``compute_attestation`` extension-data
#: convention ``ask_history.py``'s own ``_COUNTERPARTY_NAMING_KEYS`` and
#: ``capsule_emit.evidence_request``'s ``_CORRELATION_KEY_ALIASES["counterparty"]``
#: already walk. Duplicated locally (both of those are module-private, and
#: ``ask_history.py`` already imports THIS module -- see its own top matter --
#: so importing back from it would be a cycle) rather than reached into.
_COUNTERPARTY_NAMING_KEYS = frozenset({"requesting_party", "served_by_node_id", "counterparty_ref"})

#: The subject kinds the sharing-policy's relationship gate applies to
#: -- ``range`` is deliberately excluded (out of this item's scope; the
#: design note names only these three).
RELATIONSHIP_GATED_SUBJECT_KINDS = frozenset({"record", "correlation", "chain_segment"})

RELATIONSHIP_COUNTERPARTY = "counterparty"
RELATIONSHIP_IDENTIFIED = "identified"
RELATIONSHIP_STRANGER = "stranger"

#: Which relationships each ``history_segments`` tier answers. ``off``
#: answers nobody via this gate (a node that wants zero exposure, even to
#: its own past counterparties, through this door); ``peers`` answers
#: everyone, including a caller who declared no identity at all -- today's
#: pre-the sharing-policy behavior, restored by explicit opt-in.
_ALLOWED_RELATIONSHIPS_BY_TIER: dict[str, frozenset[str]] = {
    "off": frozenset(),
    "counterparties": frozenset({RELATIONSHIP_COUNTERPARTY}),
    "prospective": frozenset({RELATIONSHIP_COUNTERPARTY, RELATIONSHIP_IDENTIFIED}),
    "peers": frozenset({RELATIONSHIP_COUNTERPARTY, RELATIONSHIP_IDENTIFIED, RELATIONSHIP_STRANGER}),
}


def _iter_values_by_key(obj: Any, keys: frozenset[str]) -> Any:
    """Recursively walk *obj* (a JSON-decoded capsule record -- nested
    dicts/lists only) and yield every string value found under a key in
    *keys*, at any depth -- same generic walk as
    ``capsule_emit.evidence_request._iter_values_by_key``, duplicated per
    this module's own "duplicated here rather than reached into" precedent
    (that one is private too)."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in keys and isinstance(v, str):
                yield v
            yield from _iter_values_by_key(v, keys)
    elif isinstance(obj, list):
        for item in obj:
            yield from _iter_values_by_key(item, keys)


def classify_relationship(requester_id: str | None, ledger_entries: list[dict[str, Any]]) -> str:
    """This node's own, LOCALLY-CHECKABLE relationship to ``requester_id``:

    * ``stranger`` -- no identity was declared at all (``requester_id`` is
      ``None``/empty). The only case this function can be certain of without
      looking anything up.
    * ``counterparty`` -- ``requester_id`` names a party this node has a
      past exchange record with (walks ``_COUNTERPARTY_NAMING_KEYS`` over
      every entry, same fields ``ask_history.py``'s own reference-discovery
      walk already trusts).
    * ``identified`` -- ``requester_id`` was declared but matches no past
      exchange this node holds.

    Identity is exactly as self-attested as everything else this vocabulary
    already trusts a claim about (see the module docstring's "relationship
    policy" note) -- this function never verifies a signature over
    ``requester_id``, because the wire carries none to verify.
    """
    if not requester_id:
        return RELATIONSHIP_STRANGER
    for entry in ledger_entries:
        if requester_id in _iter_values_by_key(entry, _COUNTERPARTY_NAMING_KEYS):
            return RELATIONSHIP_COUNTERPARTY
    return RELATIONSHIP_IDENTIFIED


def relationship_allowed(relationship: str, history_segments_tier: str) -> bool:
    """Whether a caller classified as *relationship* gets an answer under
    *history_segments_tier* -- see ``_ALLOWED_RELATIONSHIPS_BY_TIER``."""
    return relationship in _ALLOWED_RELATIONSHIPS_BY_TIER[history_segments_tier]


def classify_leaf_kind(entry: dict[str, Any]) -> str:
    """the sharing-policy this repo's own ``chain_segment`` leaf
    vocabulary: everything ``capsule_emit.chain_segment``'s own
    ``_default_classify`` already names (``stamp``, ``adjudication``,
    generic ``capsule``) PLUS ``exchange_twin`` for a leaf carrying an
    ``x-mesh-poc-v1.twin_bracket_id`` -- "a half carrying a bracket id, one
    classifier line, no new record" (design note §3). Duplicates
    ``_default_classify``'s own three lines rather than importing it
    (private) -- same precedent as this module's other private-helper
    duplications.
    """
    kind = entry.get("kind")
    if kind:
        return "stamp" if kind == "checkpoint_stamp" else str(kind)
    chain = entry.get("chain")
    if isinstance(chain, dict) and chain.get("relation") == "adjudicates":
        return "adjudication"
    twin_bracket_id = (
        ((entry.get("model_attestation") or {}).get("compute_attestation") or {}).get("x-mesh-poc-v1") or {}
    ).get("twin_bracket_id")
    if twin_bracket_id:
        return "exchange_twin"
    return "capsule"


def _read_jsonl(path: Any) -> list[dict[str, Any]]:
    import json

    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _handle_served_summary_request(state: Any, request_bytes: bytes, req: Any, *, now: str | None = None) -> Any:
    from datetime import datetime, timezone

    from served_summary import COVERAGE_UNSATISFIABLE, REQUEST_MALFORMED, answer_served_summary_request

    from ledger_store_backend import read_all_capsules

    issued_at = now or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    capsule_records, _archived_segments = read_all_capsules(state.ledger_dir)
    checkpoint_lines = _read_jsonl(state.ledger_dir / "checkpoints.jsonl")
    expected_pin = (req.coverage or {}).get("expected_pin", {}).get("root") if req.coverage else None

    result = answer_served_summary_request(
        capsule_records=capsule_records,
        checkpoint_lines=checkpoint_lines,
        expected_pin=expected_pin,
    )
    if result["status"] == "ok":
        return {"v": 1, "subject_kind": req.subject.get("kind"), "derivation": SERVED_SUMMARY_DERIVATION_TOKEN, "served_summary": result["served_summary"]}
    reason = REQUEST_MALFORMED if result["status"] == REQUEST_MALFORMED else COVERAGE_UNSATISFIABLE
    return _refuse_served_summary(request_bytes, reason, state=state, issued_at=issued_at)


def _handle_chain_segment_request(
    state: Any, request_bytes: bytes, req: Any, *, issued_at: str
) -> Artifact | Refusal:
    """the sharing-policy ``chain_segment`` dispatched OUTSIDE
    ``answer()``, so this responder's own :func:`classify_leaf_kind` names
    leaves -- never ``capsule_emit.chain_segment``'s generic default. Honors
    ``coverage.expected_pin`` (same semantics as ``answer()``'s own check);
    deliberately does NOT honor ``coverage.min_freshness`` yet -- see the
    module docstring's scope note. Never paged (a chain segment is
    O(checkpoints), same as ``answer()``'s own chain_segment leg).
    """
    from capsule_emit.chain_segment import ChainSegmentError
    from capsule_emit.chain_segment import chain_segment as _chain_segment_fn
    from capsule_emit.evidence_request import Artifact
    from capsule_emit.ledger import read_ledger_entries
    from ledger_store_backend import materialize_flat_view

    request_digest = hashlib.sha256(request_bytes).hexdigest()
    signer = _resolve_state_signer(state)
    # the sharing-policy fix: chain_segment_fn needs the checkpoint's
    # OWN in-band checkpoint_stamp entries to find any checkpoint at all --
    # a plain read_all_capsules(state.ledger_dir) never sees them for a
    # node using the sibling checkpoints.jsonl convention (this module's
    # own docstring, "The plugin-ledger bridge"), so a real checkpoint
    # produced coverage_unsatisfiable unconditionally until this fix.
    # materialize_flat_view is the SAME bridge handle_evidence_request's own
    # answer() leg already uses below -- read_ledger_entries (not
    # read_ledger, which filters checkpoint_stamp out) over its output.
    entries = read_ledger_entries(materialize_flat_view(state.ledger_dir))
    if not entries:
        return _sign_refusal(request_digest, "no_such_record", signer=signer, issued_at=issued_at)

    subject = req.subject
    try:
        segment = _chain_segment_fn(
            entries,
            from_size=subject.get("from_size"),
            to_size=subject.get("to_size"),
            last=subject.get("last"),
            self_owner_id=signer.key_id,
            leaf_digests=bool(subject.get("leaf_digests", False)),
            classify=classify_leaf_kind,
        )
    except ChainSegmentError:
        return _sign_refusal(request_digest, "coverage_unsatisfiable", signer=signer, issued_at=issued_at)

    expected_pin = (req.coverage or {}).get("expected_pin")
    if expected_pin is not None:
        pin_matches = (
            segment.checkpoint.mmr_size == expected_pin["mmr_size"] and segment.checkpoint.root == expected_pin["root"]
        )
        if not pin_matches:
            return _sign_refusal(request_digest, "coverage_unsatisfiable", signer=signer, issued_at=issued_at)

    return Artifact(v=1, subject_kind="chain_segment", bundles=(segment,))


def handle_evidence_request(
    state: Any,
    request_bytes: bytes,
    *,
    now: str | None = None,
    requester_id: str | None = None,
    policy: SharePolicy | None = None,
) -> Any:
    """Answer one evidence request against ``state``'s own ledger.

    Returns a ``capsule_emit.evidence_request.Artifact``/``Refusal``, or —
    for a ``derivation: "served_summary/1"`` request — a plain dict carrying
    the served summary (see module docstring). ``now`` overrides the wall
    clock (for deterministic tests); defaults to the real UTC time.

    Deliberately passes no ``allow_forced_checkpoint`` — that parameter is
    unreleased on capsule-emit's PyPI floor this repo pins
    (``[adv-evidence-door-caps-and-subjects]``; ``requirements.txt``'s
    ``capsule-emit[mcp]>=0.7.1`` predates it). Once a release carrying it
    ships and the floor bumps, ``answer()``'s own default
    (``allow_forced_checkpoint=False``, pull-only) applies here
    automatically — no code change needed to get the safe behavior; wiring
    an explicit opt-in is a separate follow-up for whenever a node actually
    wants one.

    ``requester_id``/``policy`` — see the module docstring's
    "the sharing-policy relationship policy" note. Both default to
    ``None``, which reproduces this function's exact pre-existing behavior
    for the ``not_authorized`` RELATIONSHIP GATE specifically (every
    existing caller that predates this gate gets exactly the same
    answer/refuse decision it always did). **Narrower than "unaffected,"
    precisely stated:** a ``chain_segment`` request is dispatched to
    :func:`_handle_chain_segment_request` -- and so gets this module's own
    :func:`classify_leaf_kind` (adds the ``exchange_twin`` leaf kind) and
    drops ``coverage.min_freshness`` handling -- UNCONDITIONALLY, regardless
    of ``policy``. That dispatch is a separate, always-on classifier change
    bundled in the same the sharing-policy commit as this gate, not
    itself gated by ``policy`` -- a ``policy=None`` node's ``chain_segment``
    answers differ from pre-this-commit ``answer()`` output in leaf kind
    naming and in the (already-disclosed, see that function's own docstring)
    ``min_freshness`` gap.
    """
    from datetime import datetime, timezone

    from capsule_emit.evidence_request import RequestMalformedError, answer, parse_request

    from ledger_store_backend import materialize_flat_view, read_all_capsules

    # [mesh-fabric-vocab-alignment] side-effecting only -- see
    # log_request_purpose's docstring for the caller-invariance guarantee.
    log_request_purpose(request_bytes)

    try:
        req = parse_request(request_bytes)
    except RequestMalformedError:
        req = None

    if req is not None and req.derivation == SERVED_SUMMARY_DERIVATION_TOKEN:
        return _handle_served_summary_request(state, request_bytes, req, now=now)

    issued_at = now or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    if (
        policy is not None
        and req is not None
        and req.subject.get("kind") in RELATIONSHIP_GATED_SUBJECT_KINDS
    ):
        ledger_entries, _archived_segments = read_all_capsules(state.ledger_dir)
        relationship = classify_relationship(requester_id, ledger_entries)
        if not relationship_allowed(relationship, policy.history_segments):
            request_digest = hashlib.sha256(request_bytes).hexdigest()
            signer = _resolve_state_signer(state)
            return _sign_refusal(request_digest, REASON_NOT_AUTHORIZED, signer=signer, issued_at=issued_at)

    if req is not None and req.subject.get("kind") == "chain_segment":
        return _handle_chain_segment_request(state, request_bytes, req, issued_at=issued_at)

    # [mesh-ledger-store-migration] answer() only understands a flat JSONL
    # file -- materialize_flat_view is a no-op passthrough for a still-flat
    # ledger dir, and a fresh scratch re-derivation (never cached) for a
    # cll.ledger.store.LedgerStore-backed one, so this call's contract is
    # unchanged either way.
    return answer(
        request_bytes,
        ledger=materialize_flat_view(state.ledger_dir),
        signing_key_path=state.signing_key_path,
        now=now,
    )
