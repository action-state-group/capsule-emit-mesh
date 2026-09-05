# SPDX-License-Identifier: Apache-2.0
"""Discovery mechanism 2 (mesh-adjudication-witness-registration): register
an adjudication capsule's digest at a SCITT witness under
``subject = <judged node's key>``, so a stranger who never talked to anyone
involved can later find it via ``GET /transparency/statements?subject=<key>``
and independently recompute the citation chain.

Three pieces, matching the task's three legs:

  ``register_adjudication_capsule_witness(...)`` -- the requester's own
      choice, called AFTER ``twin_adjudicator.seal_adjudication_capsule()``,
      never automatically from it. One registration per subject (both
      providers for a ``contradicted`` verdict, all cited parties for
      ``corroborated`` -- see ``subjects_for_adjudication``) at each of the
      requester's configured witness(es); a failed registration never
      blocks the caller, same best-effort discipline as
      ``checkpointing.py``'s ``register_checkpoint`` calls.

  ``query_witness_subject(...)`` -- the stranger's half: resolve every
      statement a witness holds for a subject to its receipt + claimed
      payload digest (the adjudication capsule's own ``capsule_id``).
      Verifies NOTHING -- the witness is a witness, not a judge.

  ``recompute_adjudication_from_witness(...)`` -- the stranger's offline
      recompute, after pulling the actual adjudication capsule + its two
      cited halves through mesh evidence doors (a caller-supplied
      ``fetch_capsule`` callback, one call per capsule_id). Citation
      failure (a half that doesn't exist, doesn't verify, or was returned
      under the wrong capsule_id) is ``citation_unverified`` -- the witness
      still held the claim; only recompute rejects it.

This module never touches a live ledger or the serving path -- it is a pure
client (registration/query) plus a pure offline function (recompute).
"""
from __future__ import annotations

import base64
import json
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.request import Request, urlopen

from agent_action_capsule.verify import verify as verify_capsule
from scitt_cose.statement import build_signed_statement

from twin_adjudicator import AdjudicationHalf, AdjudicationOutcome, VERDICT_INCONCLUSIVE

__all__ = [
    "CAPSULE_ID_DIGEST_CONTENT_TYPE",
    "CITATION_UNVERIFIED",
    "RECOMPUTED",
    "RecomputeResult",
    "WitnessRegistration",
    "WitnessSubjectEntry",
    "query_witness_subject",
    "recompute_adjudication_from_witness",
    "register_adjudication_capsule_witness",
    "register_adjudication_witness",
    "subjects_for_adjudication",
]

_REGISTER_PATH = "/transparency/register-statement"
_QUERY_PATH = "/transparency/statements"

#: The COSE content-type for a bare capsule_id-digest payload -- same media
#: type `agent_action_capsule.anchor.submit_anchor` uses for its own
#: capsule_id-subject registration, so a witness sees one consistent type
#: for "the payload is a 32-byte capsule_id digest" regardless of which
#: subject value rides alongside it.
CAPSULE_ID_DIGEST_CONTENT_TYPE = "application/vnd.agent-action-capsule.capsule-id+octet-stream"

CITATION_UNVERIFIED = "citation_unverified"
RECOMPUTED = "recomputed"


def subjects_for_adjudication(
    outcome: AdjudicationOutcome, half_a: AdjudicationHalf, half_b: AdjudicationHalf
) -> list[str]:
    """The judged/cited node keys to register an adjudication capsule
    under, per the task spec: both providers for a `contradicted:<owner>`
    verdict (the exchange involved both, regardless of which one lost),
    all cited parties for `corroborated` (the same two halves, this time
    agreeing). With only two halves in this design those two sets are
    identical, so both cases reduce to "each half's known owner_id".

    Returns `[]` for `inconclusive` or a no-verdict outcome -- nothing to
    register; there is no adjudication capsule to point a subject at
    (`seal_adjudication_capsule` itself returns `None` in both cases).
    """
    if outcome.verdict is None or outcome.verdict == VERDICT_INCONCLUSIVE:
        return []
    return [owner_id for owner_id in (half_a.owner_id, half_b.owner_id) if owner_id]


@dataclass(frozen=True)
class WitnessRegistration:
    """Result of one `POST /transparency/register-statement` registering an
    adjudication capsule's digest under one subject at one witness."""

    subject: str
    capsule_id: str
    ts_url: str
    entry_hash: str
    receipt_b64: str


def register_adjudication_witness(
    capsule_id: str,
    subject: str,
    *,
    ts_url: str,
    private_key_pem: bytes,
    issuer: str,
    timeout: float = 30.0,
) -> WitnessRegistration:
    """Register `capsule_id` (an already-sealed adjudication capsule's own
    digest) at `ts_url` under `subject` (a judged/cited node's key).

    Digest-only across the wire, same discipline as
    `agent_action_capsule.anchor.submit_anchor`: only the 32-byte
    `capsule_id` digest is the COSE payload, never the capsule's content.
    Unlike `submit_anchor` (which hardcodes `subject=capsule_id`), `subject`
    here is caller-supplied and independent of `capsule_id` -- the subject
    is WHO the adjudication is about, not WHAT digest is being anchored.
    """
    payload = bytes.fromhex(capsule_id)
    statement_bytes = build_signed_statement(
        payload,
        alg="EdDSA",
        private_key_pem=private_key_pem,
        issuer=issuer,
        subject=subject,
        content_type=CAPSULE_ID_DIGEST_CONTENT_TYPE,
    )
    body = json.dumps(
        {"signed_statement_b64": base64.b64encode(statement_bytes).decode("ascii")}
    ).encode("utf-8")
    req = Request(
        ts_url.rstrip("/") + _REGISTER_PATH,
        data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    with urlopen(req, timeout=timeout) as resp:  # noqa: S310 - operator-configured witness URL
        data = json.loads(resp.read())
    return WitnessRegistration(
        subject=subject,
        capsule_id=capsule_id,
        ts_url=ts_url.rstrip("/"),
        entry_hash=data["entry_hash"],
        receipt_b64=data["receipt_b64"],
    )


def register_adjudication_capsule_witness(
    capsule_id: str,
    subjects: list[str],
    *,
    ts_urls: list[str],
    private_key_pem: bytes,
    issuer: str,
    timeout: float = 30.0,
    on_error: Callable[[str, str, Exception], None] | None = None,
) -> list[WitnessRegistration]:
    """Register one adjudication capsule under every subject in `subjects`
    (see `subjects_for_adjudication`) at every witness in `ts_urls`.

    Registration is the requester's OWN CHOICE -- this is never called
    automatically from `twin_adjudicator.seal_adjudication_capsule()`.

    Best-effort per (subject, ts_url) pair, same discipline as
    `checkpointing.py`'s witness registration: an unreachable witness never
    raises and never blocks the others -- `on_error(subject, ts_url, exc)`
    is invoked if supplied, else the failure is silently skipped (the
    adjudication capsule itself is already sealed and stored locally
    regardless of how many witnesses accepted it).
    """
    results: list[WitnessRegistration] = []
    for subject in subjects:
        for ts_url in ts_urls:
            try:
                results.append(
                    register_adjudication_witness(
                        capsule_id,
                        subject,
                        ts_url=ts_url,
                        private_key_pem=private_key_pem,
                        issuer=issuer,
                        timeout=timeout,
                    )
                )
            except Exception as exc:  # noqa: BLE001 - witness registration never blocks the caller
                if on_error is not None:
                    on_error(subject, ts_url, exc)
    return results


@dataclass(frozen=True)
class WitnessSubjectEntry:
    """One statement a witness holds for a queried subject -- an
    UNVERIFIED claim (see `GET /transparency/statements`'s docstring)."""

    entry_hash: str
    capsule_id: str | None
    receipt_b64: str
    leaf_index: int
    tree_size: int


def query_witness_subject(ts_url: str, subject: str, *, timeout: float = 30.0) -> list[WitnessSubjectEntry]:
    """Resolve every statement `ts_url` holds for `subject` to its receipt +
    claimed capsule_id digest. Verifies nothing; a stranger must pull the
    actual record via its own evidence door and recompute (see
    `recompute_adjudication_from_witness`) before trusting any of it."""
    url = f"{ts_url.rstrip('/')}{_QUERY_PATH}?subject={urllib.parse.quote(subject, safe='')}"
    req = Request(url, headers={"Accept": "application/json"})
    with urlopen(req, timeout=timeout) as resp:  # noqa: S310 - operator-configured witness URL
        data = json.loads(resp.read())
    return [
        WitnessSubjectEntry(
            entry_hash=e["entry_hash"],
            capsule_id=e.get("capsule_id_digest"),
            receipt_b64=e["receipt_b64"],
            leaf_index=e["leaf_index"],
            tree_size=e["tree_size"],
        )
        for e in data["entries"]
    ]


@dataclass(frozen=True)
class RecomputeResult:
    """Outcome of recomputing an adjudication capsule pulled via a witness
    subject lookup. `status == CITATION_UNVERIFIED` means the claim did not
    hold up under independent verification -- the witness still holds the
    claim (it is a witness, not a judge); only THIS recompute rejects it."""

    status: str
    reason: str | None = None
    twin_owner_distinct: bool | None = None
    declared_twin_owner_distinct: bool | None = None
    verdict_consistent: bool | None = None


def recompute_adjudication_from_witness(
    adjudication_capsule: dict[str, Any],
    fetch_capsule: Callable[[str], dict[str, Any] | None],
) -> RecomputeResult:
    """Independently recompute what an adjudication capsule pulled via a
    witness subject lookup actually cites, offline, no trust in the
    witness or the requester who registered it.

    `fetch_capsule(capsule_id)` is the caller's evidence-door pull (e.g.
    `POST /evidence-request {subject: {kind: "record", capsule_id}}`
    against whichever mesh node the caller believes holds it, then
    `Bundle.receipt` out of the returned `Artifact` -- see
    `ask_history.py` / `evidence_server.py`) -- this module has no
    network/mesh-topology knowledge of its own.

    Order of checks, each a distinct `citation_unverified` reason:
      1. the adjudication capsule itself must pass its own verify().
      2. both `half_a_capsule_id`/`half_b_capsule_id` must be present.
      3. each cited half must be FOUND via `fetch_capsule` -- a half
         nobody will hand over (or that never existed) is unverified.
      4. each returned half must self-report the capsule_id it was
         fetched BY -- never trust a well-formed-but-substituted record
         (same bind-subject-to-capsule_id discipline as
         `mesh-verify-bind-statement-to-capsuleid`).
      5. each cited half must pass its own verify() -- a forged half is
         exactly the mutant this recompute exists to catch.

    Only once all five hold does this recompute the one thing derivable
    without the original disclosed preimages (which a stranger never has):
    `twin_owner_distinct`, cross-checked against what the adjudication
    capsule declared. A full transcript re-diff needs the disclosed
    preimages too (PR #79's local-only store) and is out of scope for a
    stranger recompute -- this is the honest citation-chain floor, not a
    claim to redo the twin comparison itself.
    """
    if not verify_capsule(adjudication_capsule).ok:
        return RecomputeResult(status=CITATION_UNVERIFIED, reason="adjudication_capsule_forged")

    adjudication = (
        (adjudication_capsule.get("model_attestation") or {}).get("compute_attestation") or {}
    ).get("adjudication") or {}
    half_a_id = adjudication.get("half_a_capsule_id")
    half_b_id = adjudication.get("half_b_capsule_id")
    if not half_a_id or not half_b_id:
        return RecomputeResult(status=CITATION_UNVERIFIED, reason="missing_half_citation")

    halves: dict[str, AdjudicationHalf] = {}
    for label, half_id in (("half_a", half_a_id), ("half_b", half_b_id)):
        fetched = fetch_capsule(half_id)
        if fetched is None:
            return RecomputeResult(status=CITATION_UNVERIFIED, reason=f"{label}_not_found")
        if fetched.get("capsule_id") != half_id:
            return RecomputeResult(status=CITATION_UNVERIFIED, reason=f"{label}_capsule_id_mismatch")
        if not verify_capsule(fetched).ok:
            return RecomputeResult(status=CITATION_UNVERIFIED, reason=f"{label}_forged")
        halves[label] = AdjudicationHalf.from_capsule_and_disclosure(fetched, {})

    recomputed_distinct: bool | None = None
    if halves["half_a"].owner_id is not None and halves["half_b"].owner_id is not None:
        recomputed_distinct = halves["half_a"].owner_id != halves["half_b"].owner_id

    declared_distinct = adjudication.get("twin_owner_distinct")
    verdict_consistent = recomputed_distinct == declared_distinct if recomputed_distinct is not None else None

    return RecomputeResult(
        status=RECOMPUTED,
        twin_owner_distinct=recomputed_distinct,
        declared_twin_owner_distinct=declared_distinct,
        verdict_consistent=verdict_consistent,
    )
