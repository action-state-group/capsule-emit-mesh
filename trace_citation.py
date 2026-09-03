#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""trace_citation -- close the top rung of the measurement ladder BY COMPOSITION.

A mesh capsule cites a foreign TRACE Trust Record (`agentrust-io/trace-spec`) by a
CPB typed digest reference -- the same `{type, digest_alg, digest}` shape
`node_ownership.owner_cert_reference` / `mesh_coordinator_receipt_emitter` already use,
extended with a `slot` -- and carries the record's TDX quote alongside it. This module
grades what that citation can actually support.

Nothing here re-implements attestation. TDX quote parsing/verification is
`agent_manifest._tdx_verify` (PyPI `agent-manifest`), imported unmodified -- the
standing rule for this rung is depend on their verifier, never re-implement it.
Record-envelope authenticity, where a trusted issuer key is configured, is
`agentrust_trace.sign.verify_record` (PyPI `agentrust-trace`), same rule.

THREE GRADES, never a boolean (agentrust-io/trace-spec#277, Imran Siddique's own
correction after running our mutant set against a real capture):

  unattested          no verifiable hardware evidence cited (absent, malformed,
                       by-reference-only, unsupported format, or citation/signature
                       mismatch)
  platform-attested   genuine Intel silicon reported this measurement -- the quote
                       verifies AND the cited record's declared measurement equals
                       the quote's MRTD. Does NOT establish that this record's
                       execution happened on that silicon, and does NOT establish
                       TCB currency (agent-manifest's verifier checks the DCAP
                       signature chain to a pinned Intel root; it does not call
                       Intel's live PCS/ITA, so TCB freshness/revocation is a named
                       residual, not a claim this grade makes).
  attested            the above, AND the quote's guest-controlled REPORT_DATA field
                       commits to the key that signs the cited record -- silicon
                       signs quote -> quote commits key -> key signs record, so
                       every claim in the record is transitively rooted in silicon.
                       UNREACHABLE from any artifact this codebase holds today: both
                       captured quotes bind a manifest digest, not a record-signing
                       key (see tests/fixtures/tdx-attestation/README.md).

THE LIFT-RULE CORRECTION this module exists to encode: measurement-matching binds a
record to a *measurement*, not to a *quote*. `tdx_quote.bin` and
`tdx_quote_manifest.bin` come from ONE TD -- same MRTD, different REPORT_DATA -- so
swapping which of the two backs a citation still satisfies the measurement check.
That is why `platform-attested` is capped at "genuine silicon reported this
measurement" and never rises to "this execution happened there" on measurement
match alone; see the substitution mutant in tests/test_trace_citation.py.

Grade honesty on the MODEL claim is a SEPARATE, independent computation
(`grade_model_claim`) -- a hardware grade on the record is never passed to it and
never propagates to the claims inside the record (trace-spec#277 section 6.1; the
same section documents a first-draft bug that graded the model claim by reading a
producer-written advisory field instead of recomputing the binding -- exactly the
assurance-laundering shape this module's tests confirm we do not repeat).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
from dataclasses import dataclass
from typing import Any, Optional

from agent_manifest._tdx_verify import (
    TdxVerificationError,
    parse_tdx_quote,
    verify_tdx_quote,
)

__all__ = [
    "TRACE_RECORD_REF_TYPE",
    "DIGEST_ALG_SHA256",
    "GRADE_UNATTESTED",
    "GRADE_PLATFORM_ATTESTED",
    "GRADE_ATTESTED",
    "MODEL_CLAIM_ABSENT",
    "MODEL_CLAIM_SELF_REPORTED",
    "MODEL_CLAIM_ATTESTED",
    "CARD_TEXT",
    "FORBIDDEN_CARD_PHRASES",
    "TeeCitationResult",
    "trace_record_reference",
    "citation_matches",
    "grade_tee_citation",
    "grade_model_claim",
]

# ---------------------------------------------------------------------------
# Typed digest reference -- the CPB shape node_ownership.py/mesh_coordinator_
# receipt_emitter.py already use, reused here rather than inventing a second
# convention. `slot` names which evidence slot on the citing capsule this
# reference fills (e.g. "runtime.tee_attestation") -- the fourth member the
# other two call-sites don't need, because they cite exactly one thing.
# ---------------------------------------------------------------------------
TRACE_RECORD_REF_TYPE = "trace-record"
DIGEST_ALG_SHA256 = "SHA-256"

GRADE_UNATTESTED = "unattested"
GRADE_PLATFORM_ATTESTED = "platform-attested"
GRADE_ATTESTED = "attested"

MODEL_CLAIM_ABSENT = "absent"
MODEL_CLAIM_SELF_REPORTED = "self-reported"
MODEL_CLAIM_ATTESTED = "attested"

# The three-state discipline this repo's viewer already uses
# (capsule_accountability_tab.STATE_*), duplicated as plain strings rather than
# imported, so this module has no dependency on the viewer -- the viewer depends on
# this module, not the other way around.
_SIG_ABSENT = "absent"
_SIG_VERIFIED = "verified"
_SIG_FAILED = "failed"

# Fixed, reviewed caveat text per grade. Card rendering MUST use these strings
# verbatim rather than composing its own -- see test_trace_citation.py's
# messaging-guard test, which greps every value here for the phrases a card must
# never say.
CARD_TEXT = {
    GRADE_UNATTESTED: (
        "no verifiable hardware evidence cited -- every runtime claim here is the "
        "issuer's word"
    ),
    GRADE_PLATFORM_ATTESTED: (
        "genuine Intel silicon reported this measurement. This is NOT a claim that "
        "this record's execution happened on that silicon, and NOT a claim that the "
        "platform's TCB is current -- the verifier checks the DCAP signature chain "
        "to a pinned Intel root only, offline, with no live PCS/ITA call."
    ),
    GRADE_ATTESTED: (
        "genuine Intel silicon reported this measurement, and the quote's "
        "REPORT_DATA commits to the key that signs this record -- unreachable from "
        "any artifact this codebase holds today."
    ),
}

FORBIDDEN_CARD_PHRASES = (
    "tcb current",
    "tcb is up to date",
    "this execution happened",
    "executed here",
    "executed on this",
    "ran here",
)


def trace_record_reference(record_bytes: bytes, *, slot: str) -> dict[str, Any]:
    """The cited TRACE record as a CPB typed digest reference.

    Computed directly over the record's own bytes -- the same bytes carried
    alongside the citing capsule -- so the reference is unforgeable without
    reproducing those exact bytes, and changes if the record is tampered or
    substituted for a different one after citation.
    """
    return {
        "type": TRACE_RECORD_REF_TYPE,
        "digest_alg": DIGEST_ALG_SHA256,
        "digest": hashlib.sha256(record_bytes).hexdigest(),
        "slot": slot,
    }


def citation_matches(record_bytes: bytes, reference: dict[str, Any]) -> bool:
    """True iff *record_bytes* is byte-identical to what *reference* cites.

    The record is a foreign-signed artifact and MUST be cited byte-identically,
    never re-minted -- this is the check that catches a forged, substituted, or
    stale citation before any attestation logic runs.
    """
    if reference.get("type") != TRACE_RECORD_REF_TYPE:
        return False
    if reference.get("digest_alg") != DIGEST_ALG_SHA256:
        return False
    digest = reference.get("digest")
    if not isinstance(digest, str):
        return False
    return hmac.compare_digest(hashlib.sha256(record_bytes).hexdigest(), digest.lower())


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


@dataclass
class TeeCitationResult:
    """The verdict a mesh capsule's TEE-via-citation rung earns. A result, not an
    exception -- every rejection is a value the caller can render, same discipline
    as OwnershipRecheck / verify_witness_stamp_tristate."""

    grade: str
    reason: str
    card_text: str
    mrtd: Optional[str] = None
    quote_verifies: Optional[bool] = None
    citation_matches: Optional[bool] = None
    record_signature_state: str = _SIG_ABSENT
    record_signature_detail: str = "no trusted issuer key configured"


def _unattested(
    reason: str,
    *,
    citation_ok: Optional[bool] = None,
    quote_verifies: Optional[bool] = None,
    mrtd: Optional[str] = None,
    record_signature_state: str = _SIG_ABSENT,
    record_signature_detail: str = "no trusted issuer key configured",
) -> TeeCitationResult:
    return TeeCitationResult(
        grade=GRADE_UNATTESTED,
        reason=reason,
        card_text=CARD_TEXT[GRADE_UNATTESTED],
        mrtd=mrtd,
        quote_verifies=quote_verifies,
        citation_matches=citation_ok,
        record_signature_state=record_signature_state,
        record_signature_detail=record_signature_detail,
    )


def _check_record_signature(
    cited_record: dict[str, Any], trusted_issuer_jwk: Optional[dict[str, Any]]
) -> tuple[str, str]:
    """Three-state, never two: no configured key is ABSENT context (not a failure);
    a key that fails to verify is FAILED (evidence of tampering, never retried).

    Uses `agentrust_trace.sign.verify_record` as a dependency when a trusted key is
    configured -- never re-implemented. Import is local: a deployment that has no
    registry of AgenTrust issuer keys yet (true today, pre-2026-09-09) never needs
    `agentrust-trace` installed at all.
    """
    if trusted_issuer_jwk is None:
        return _SIG_ABSENT, (
            "no trusted issuer key configured -- record authenticity not checked; "
            "citation-digest match is the only binding available today"
        )
    from agentrust_trace.sign import verify_record

    try:
        # max_age_seconds=None: freshness of a live nonce is not this citation's
        # concern -- a hardware attestation record legitimately gets cited long
        # after capture (that's the whole point of citing it instead of re-minting
        # it). Signature validity is what this check is for; staleness is a
        # separate, orthogonal policy this module does not impose.
        verify_record(cited_record, trusted_issuer_jwk, max_age_seconds=None)
        return _SIG_VERIFIED, "record signature verifies against the configured trusted issuer key"
    except Exception as e:  # noqa: BLE001 - a result, not a propagated exception
        return _SIG_FAILED, f"record signature check failed: {type(e).__name__}: {e}"


def grade_tee_citation(
    *,
    reference: dict[str, Any],
    cited_record: dict[str, Any],
    cited_record_bytes: bytes,
    quote_bytes: Optional[bytes],
    trusted_issuer_jwk: Optional[dict[str, Any]] = None,
) -> TeeCitationResult:
    """Grade a mesh capsule's citation of a foreign TRACE Trust Record's TDX
    evidence. Never raises: every rejection is an `unattested` result carrying a
    `reason`, so a bad citation is a verdict the viewer can render, not a crash.

    Order matters (mirrors trace-spec#277 rule 1): the citation is checked BEFORE
    any attestation logic runs, because the evidence is a member of a specific
    signed record -- verifying a quote before confirming which record it came from
    would check hardware this citation never actually committed to.
    """
    # 1. Citation integrity: byte-identical, never re-minted.
    if not citation_matches(cited_record_bytes, reference):
        return _unattested(
            "cited record bytes do not match the reference digest -- forged, "
            "stale, or substituted citation",
            citation_ok=False,
        )

    # 2. Record self-consistency/authenticity, where we have a trusted key for it.
    #    A FAILED signature rejects outright, same as trace-spec#277's envelope-first
    #    rule -- a tampered record earns no grade regardless of what its evidence says.
    sig_state, sig_detail = _check_record_signature(cited_record, trusted_issuer_jwk)
    if sig_state == _SIG_FAILED:
        return _unattested(
            f"cited record envelope failed: {sig_detail}",
            citation_ok=True,
            record_signature_state=sig_state,
            record_signature_detail=sig_detail,
        )

    runtime = cited_record.get("runtime") or {}
    evidence = runtime.get("evidence")

    # 3. Evidence presence/shape. Absent or by-reference-only is a DOWNGRADE, never
    #    a rejection: a record with no evidence is a record with no evidence, and a
    #    URI a verifier hasn't fetched has verified nothing (offline-verifiability
    #    is the property; a pointer does not earn what fetching it might).
    if not evidence:
        return _unattested(
            "cited record carries no runtime.evidence",
            citation_ok=True,
            record_signature_state=sig_state,
            record_signature_detail=sig_detail,
        )
    if evidence.get("format") != "tdx-quote-v4":
        return _unattested(
            f"unsupported evidence format {evidence.get('format')!r}",
            citation_ok=True,
            record_signature_state=sig_state,
            record_signature_detail=sig_detail,
        )
    if quote_bytes is None:
        return _unattested(
            "no quote bytes carried alongside the citation -- by-reference evidence "
            "has verified nothing",
            citation_ok=True,
            record_signature_state=sig_state,
            record_signature_detail=sig_detail,
        )
    if runtime.get("platform") != "intel-tdx":
        return _unattested(
            f"platform {runtime.get('platform')!r} is not what this evidence roots",
            citation_ok=True,
            record_signature_state=sig_state,
            record_signature_detail=sig_detail,
        )

    # 4. Quote verification -- agent_manifest, never re-implemented.
    try:
        ok = verify_tdx_quote(quote_bytes)
    except TdxVerificationError as e:
        return _unattested(
            f"quote malformed or verification error: {e}",
            citation_ok=True,
            quote_verifies=False,
            record_signature_state=sig_state,
            record_signature_detail=sig_detail,
        )
    if ok is not True:
        return _unattested(
            "quote signature chain did not verify",
            citation_ok=True,
            quote_verifies=False,
            record_signature_state=sig_state,
            record_signature_detail=sig_detail,
        )

    parsed = parse_tdx_quote(quote_bytes)
    mrtd_hex = parsed.mrtd.hex()

    # 5. The binding rule: REQUIRED, runtime.measurement == the MRTD the verifier
    #    reads out of the quote. A valid quote proves a TD ran; it says nothing
    #    about which measurement THIS citation is entitled to claim until the two
    #    are compared. Disagreement is a rejection, not a downgrade -- the citation
    #    made a specific, checkable, false statement.
    claimed = runtime.get("measurement")
    if not claimed:
        return _unattested(
            "cited record declares no runtime.measurement",
            citation_ok=True,
            quote_verifies=True,
            mrtd=mrtd_hex,
            record_signature_state=sig_state,
            record_signature_detail=sig_detail,
        )
    normalized_claimed = str(claimed).rsplit(":", 1)[-1].strip().lower()
    if normalized_claimed != mrtd_hex.lower():
        return _unattested(
            f"runtime.measurement ({claimed}) does not match the quote's MRTD "
            f"({mrtd_hex}) -- citation mismatch",
            citation_ok=True,
            quote_verifies=True,
            mrtd=mrtd_hex,
            record_signature_state=sig_state,
            record_signature_detail=sig_detail,
        )

    # 6. The key-binding rule -- the whole distance between the top grade and the
    #    middle one. Always attempted; never assumed unreachable without checking,
    #    even though every artifact this codebase holds today makes it unreachable.
    reachable_attested = False
    cnf_jwk = (cited_record.get("cnf") or {}).get("jwk") or {}
    if cnf_jwk.get("kty") == "OKP" and cnf_jwk.get("x"):
        try:
            pub_raw = _b64url_decode(cnf_jwk["x"])
            reachable_attested = hmac.compare_digest(
                parsed.report_data[:32], hashlib.sha256(pub_raw).digest()
            )
        except Exception:  # noqa: BLE001 - a malformed jwk just fails the check
            reachable_attested = False

    grade = GRADE_ATTESTED if reachable_attested else GRADE_PLATFORM_ATTESTED
    reason = (
        "REPORT_DATA commits to this record's signing key"
        if reachable_attested
        else (
            "genuine silicon reported this measurement; REPORT_DATA in this quote "
            "binds a manifest digest, not a record-signing key, so the top grade is "
            "unreachable from this evidence regardless of which valid quote sharing "
            "this MRTD is cited"
        )
    )
    return TeeCitationResult(
        grade=grade,
        reason=reason,
        card_text=CARD_TEXT[grade],
        mrtd=mrtd_hex,
        quote_verifies=True,
        citation_matches=True,
        record_signature_state=sig_state,
        record_signature_detail=sig_detail,
    )


def grade_model_claim(cited_record: dict[str, Any], quote_bytes: Optional[bytes]) -> str:
    """Grade the model claim's OWN evidence -- deliberately NOT a parameter of
    `grade_tee_citation` and never given that function's result. A hardware grade
    on the record does not propagate to the claims inside it (trace-spec#277 §6.1):
    `weights_digest` is attested only where a verifier can RECOMPUTE the binding
    from the evidence, never by reading an advisory field a producer wrote.

    This mirrors trace-spec#277's own `grade_model_claim` reference rule, including
    the fix for its first-draft bug: that draft read `evidence.binds` (a producer's
    stated intent) to decide the grade, which would let a producer raise its own
    claim by writing a string -- the exact laundering this function's non-
    propagation contract exists to forbid. This implementation never reads
    `evidence.binds` or any other advisory field; it recomputes, or it says
    self-reported.
    """
    model = cited_record.get("model") or {}
    digest = model.get("weights_digest")
    if digest is None:
        return MODEL_CLAIM_ABSENT
    if quote_bytes is None:
        return MODEL_CLAIM_SELF_REPORTED
    try:
        parsed = parse_tdx_quote(quote_bytes)
    except TdxVerificationError:
        return MODEL_CLAIM_SELF_REPORTED
    report_data = parsed.report_data[:32]
    algo, _, hexdigest = str(digest).partition(":")
    candidates = [hashlib.sha256(str(digest).encode()).digest()]
    if algo == "sha256" and len(hexdigest) == 64:
        try:
            candidates.append(bytes.fromhex(hexdigest))
        except ValueError:
            pass
    if any(hmac.compare_digest(report_data, c) for c in candidates):
        return MODEL_CLAIM_ATTESTED
    return MODEL_CLAIM_SELF_REPORTED
