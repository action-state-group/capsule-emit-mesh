# SPDX-License-Identifier: Apache-2.0
"""trace_citation.py: composing the top measurement rung by citing a foreign TRACE
Trust Record's TDX evidence.

Focus: (1) the happy path grades platform-attested off a REAL captured quote via
agent-manifest's verifier; (2) the SUBSTITUTION MUTANT (red-before-green per
mesh-tee-rung-trace-citation item 3) -- swapping which of two genuinely-valid,
same-MRTD quotes backs a citation must never change the grade or the card text,
proving the middle grade never rises to "this execution happened there" on
measurement match alone; (3) every other mutant (forged citation, absent quote,
mismatched measurement, wrong platform, forged quote, tampered record envelope)
grades no higher than unattested; (4) weights_digest non-propagation.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from agent_manifest._tdx_verify import parse_tdx_quote

from trace_citation import (
    CARD_TEXT,
    FORBIDDEN_CARD_PHRASES,
    GRADE_ATTESTED,
    GRADE_PLATFORM_ATTESTED,
    GRADE_UNATTESTED,
    MODEL_CLAIM_ABSENT,
    MODEL_CLAIM_ATTESTED,
    MODEL_CLAIM_SELF_REPORTED,
    citation_matches,
    grade_model_claim,
    grade_tee_citation,
    trace_record_reference,
)

FIXTURES = Path(__file__).parent / "fixtures" / "tdx-attestation"
QUOTE_A = (FIXTURES / "tdx_quote.bin").read_bytes()
QUOTE_B = (FIXTURES / "tdx_quote_manifest.bin").read_bytes()
SHARED_MRTD = parse_tdx_quote(QUOTE_A).mrtd.hex()

assert parse_tdx_quote(QUOTE_B).mrtd.hex() == SHARED_MRTD, "fixtures must share one MRTD"
assert parse_tdx_quote(QUOTE_A).report_data != parse_tdx_quote(QUOTE_B).report_data, (
    "fixtures must differ in REPORT_DATA -- otherwise the substitution mutant below tests nothing"
)


def _record(*, measurement: str | None = SHARED_MRTD, platform="intel-tdx", weights_digest=None, cnf=None):
    runtime: dict = {"platform": platform, "evidence": {"format": "tdx-quote-v4", "collateral": "embedded"}}
    if measurement is not None:
        runtime["measurement"] = f"sha384:{measurement}"
    record = {
        "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
        "subject": "spiffe://trust.example.org/agent/evidence-demo/prod",
        "runtime": runtime,
        "model": {"provider": "meta", "model_id": "llama-3.3-70b-instruct"},
    }
    if weights_digest is not None:
        record["model"]["weights_digest"] = weights_digest
    if cnf is not None:
        record["cnf"] = cnf
    return record


def _record_bytes(record: dict) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":")).encode()


def _cite(record: dict, *, slot="runtime.tee_attestation") -> tuple[bytes, dict]:
    record_bytes = _record_bytes(record)
    return record_bytes, trace_record_reference(record_bytes, slot=slot)


# --------------------------------------------------------------------------- happy path


def test_platform_attested_with_real_quote():
    record = _record()
    record_bytes, reference = _cite(record)
    result = grade_tee_citation(
        reference=reference, cited_record=record, cited_record_bytes=record_bytes, quote_bytes=QUOTE_A
    )
    assert result.grade == GRADE_PLATFORM_ATTESTED
    assert result.mrtd == SHARED_MRTD
    assert result.quote_verifies is True
    assert result.citation_matches is True
    assert result.card_text == CARD_TEXT[GRADE_PLATFORM_ATTESTED]


def test_reference_shape_is_the_shared_cpb_typed_digest_convention():
    record_bytes, reference = _cite(_record(), slot="runtime.tee_attestation")
    assert reference == {
        "type": "trace-record",
        "digest_alg": "SHA-256",
        "digest": hashlib.sha256(record_bytes).hexdigest(),
        "slot": "runtime.tee_attestation",
    }


# --------------------------------------------------------------------------- the substitution mutant


def test_substitution_mutant_never_escalates_and_never_changes_the_card():
    """Swap which of the two genuinely-valid, same-MRTD quotes backs a citation.

    Both quotes verify on their own and share an MRTD, so rule 4 (measurement must
    equal the evidence's MRTD) is satisfied either way -- this is the documented
    LIMIT (trace-spec#277 §7.1), not a bug: the rule binds a record to a
    *measurement*, never to a *quote*. The required property is that our grading
    can never be tricked into reading the swap as "this execution happened there":
    the grade and the exact card text must be IDENTICAL regardless of which real
    quote is cited, and the reason text must explain the swap is inert, not silent.
    """
    record = _record()
    record_bytes, reference = _cite(record)

    result_a = grade_tee_citation(
        reference=reference, cited_record=record, cited_record_bytes=record_bytes, quote_bytes=QUOTE_A
    )
    result_b = grade_tee_citation(
        reference=reference, cited_record=record, cited_record_bytes=record_bytes, quote_bytes=QUOTE_B
    )

    for result in (result_a, result_b):
        assert result.grade == GRADE_PLATFORM_ATTESTED, "swap must not escalate to attested"
        assert result.grade != GRADE_ATTESTED

    assert result_a.card_text == result_b.card_text == CARD_TEXT[GRADE_PLATFORM_ATTESTED]
    assert result_a.reason != result_b.reason or "regardless of which valid quote" in result_a.reason

    for result in (result_a, result_b):
        lowered = (result.card_text + " " + result.reason).lower()
        for phrase in FORBIDDEN_CARD_PHRASES:
            assert phrase not in lowered, f"forbidden phrase {phrase!r} leaked for grade {result.grade}"


def test_messaging_guard_no_card_text_ever_overclaims():
    """Grep-able guard (same shape as the O3 split-replay messaging guard): none of
    the reviewed, shipped card strings may say a TCB-currency or execution-location
    claim this grade does not support."""
    for grade, text in CARD_TEXT.items():
        lowered = text.lower()
        for phrase in FORBIDDEN_CARD_PHRASES:
            assert phrase not in lowered, f"{grade} card text contains forbidden phrase {phrase!r}"


# --------------------------------------------------------------------------- other mutants: no lift


def test_forged_citation_digest_mismatch_no_lift():
    record = _record()
    record_bytes, reference = _cite(record)
    reference["digest"] = "0" * 64  # forged: does not match the record's actual bytes
    result = grade_tee_citation(
        reference=reference, cited_record=record, cited_record_bytes=record_bytes, quote_bytes=QUOTE_A
    )
    assert result.grade == GRADE_UNATTESTED
    assert result.citation_matches is False


def test_substituted_record_under_the_same_reference_no_lift():
    """The reference cites record X's bytes; presenting record Y instead (even one
    that would otherwise grade fine) must be caught by the digest check, not waved
    through because Y also looks plausible."""
    record_x = _record()
    record_x_bytes, reference = _cite(record_x)
    record_y = _record(measurement=SHARED_MRTD)  # a different (equal-content but distinct-object) record
    record_y_bytes = _record_bytes(record_y)
    assert record_y_bytes == record_x_bytes  # sanity: same content serializes identically
    # Force genuine divergence: Y has an extra field X never had.
    record_y_bytes = _record_bytes({**record_y, "extra": "tampered"})
    result = grade_tee_citation(
        reference=reference, cited_record=record_y, cited_record_bytes=record_y_bytes, quote_bytes=QUOTE_A
    )
    assert result.grade == GRADE_UNATTESTED
    assert result.citation_matches is False


def test_absent_quote_no_lift():
    record = _record()
    record_bytes, reference = _cite(record)
    result = grade_tee_citation(
        reference=reference, cited_record=record, cited_record_bytes=record_bytes, quote_bytes=None
    )
    assert result.grade == GRADE_UNATTESTED
    assert "no quote bytes" in result.reason


def test_absent_evidence_block_no_lift():
    record = _record()
    del record["runtime"]["evidence"]
    record_bytes, reference = _cite(record)
    result = grade_tee_citation(
        reference=reference, cited_record=record, cited_record_bytes=record_bytes, quote_bytes=QUOTE_A
    )
    assert result.grade == GRADE_UNATTESTED
    assert "no runtime.evidence" in result.reason


def test_measurement_mismatch_no_lift_even_though_quote_verifies():
    record = _record(measurement="ff" * 48)  # a measurement no captured quote reports
    record_bytes, reference = _cite(record)
    result = grade_tee_citation(
        reference=reference, cited_record=record, cited_record_bytes=record_bytes, quote_bytes=QUOTE_A
    )
    assert result.grade == GRADE_UNATTESTED
    assert result.quote_verifies is True  # the quote itself is genuine
    assert "citation mismatch" in result.reason


def test_platform_mismatch_no_lift():
    record = _record(platform="amd-sev-snp")
    record_bytes, reference = _cite(record)
    result = grade_tee_citation(
        reference=reference, cited_record=record, cited_record_bytes=record_bytes, quote_bytes=QUOTE_A
    )
    assert result.grade == GRADE_UNATTESTED
    assert "is not what this evidence roots" in result.reason


def test_forged_quote_bytes_no_lift():
    record = _record()
    record_bytes, reference = _cite(record)
    forged = bytearray(QUOTE_A)
    forged[100] ^= 0xFF  # flip a byte inside the signed body
    result = grade_tee_citation(
        reference=reference, cited_record=record, cited_record_bytes=record_bytes, quote_bytes=bytes(forged)
    )
    assert result.grade == GRADE_UNATTESTED
    assert result.quote_verifies is False


def test_malformed_quote_bytes_no_lift():
    record = _record()
    record_bytes, reference = _cite(record)
    result = grade_tee_citation(
        reference=reference, cited_record=record, cited_record_bytes=record_bytes, quote_bytes=b"not a quote"
    )
    assert result.grade == GRADE_UNATTESTED


def test_unsupported_evidence_format_no_lift():
    record = _record()
    record["runtime"]["evidence"]["format"] = "sev-snp-report-v2"
    record_bytes, reference = _cite(record)
    result = grade_tee_citation(
        reference=reference, cited_record=record, cited_record_bytes=record_bytes, quote_bytes=QUOTE_A
    )
    assert result.grade == GRADE_UNATTESTED
    assert "unsupported evidence format" in result.reason


def test_no_declared_measurement_no_lift():
    record = _record(measurement=None)
    record_bytes, reference = _cite(record)
    result = grade_tee_citation(
        reference=reference, cited_record=record, cited_record_bytes=record_bytes, quote_bytes=QUOTE_A
    )
    assert result.grade == GRADE_UNATTESTED
    assert "declares no runtime.measurement" in result.reason


# --------------------------------------------------------------------------- record-envelope mutant


def test_tampered_record_envelope_rejects_even_with_a_perfect_quote():
    """When a trusted issuer key IS configured (the future-registry case), a
    record whose signature does not verify against it earns no grade at all --
    envelope-first, mirroring trace-spec#277 rule 1: a valid quote does not save a
    record nobody trustworthy actually signed."""
    agentrust_trace = pytest.importorskip("agentrust_trace")
    from agentrust_trace.sign import generate_key, key_to_jwk, sign_record

    signing_key = generate_key()
    trusted_jwk = key_to_jwk(signing_key)
    record = _record()
    record["iat"] = 1753056000
    signed = sign_record(record, signing_key)

    # Tamper AFTER signing -- the record we actually cite no longer matches what was signed.
    tampered = {**signed, "subject": "spiffe://trust.example.org/agent/attacker/prod"}
    tampered_bytes = _record_bytes(tampered)
    reference = trace_record_reference(tampered_bytes, slot="runtime.tee_attestation")

    result = grade_tee_citation(
        reference=reference,
        cited_record=tampered,
        cited_record_bytes=tampered_bytes,
        quote_bytes=QUOTE_A,
        trusted_issuer_jwk=trusted_jwk,
    )
    assert result.grade == GRADE_UNATTESTED
    assert result.record_signature_state == "failed"


def test_untampered_signed_record_still_grades_platform_attested():
    pytest.importorskip("agentrust_trace")
    from agentrust_trace.sign import generate_key, key_to_jwk, sign_record

    signing_key = generate_key()
    trusted_jwk = key_to_jwk(signing_key)
    record = _record()
    record["iat"] = 1753056000
    signed = sign_record(record, signing_key)
    signed_bytes = _record_bytes(signed)
    reference = trace_record_reference(signed_bytes, slot="runtime.tee_attestation")

    result = grade_tee_citation(
        reference=reference,
        cited_record=signed,
        cited_record_bytes=signed_bytes,
        quote_bytes=QUOTE_A,
        trusted_issuer_jwk=trusted_jwk,
    )
    assert result.grade == GRADE_PLATFORM_ATTESTED
    assert result.record_signature_state == "verified"


# --------------------------------------------------------------------------- weights_digest non-propagation


def test_model_claim_absent_when_no_weights_digest():
    assert grade_model_claim(_record(), QUOTE_A) == MODEL_CLAIM_ABSENT


def test_model_claim_self_reported_by_default_even_when_hardware_is_platform_attested():
    """A hardware grade never propagates: this record's hardware would grade
    platform-attested (see test_platform_attested_with_real_quote), yet an
    arbitrary weights_digest the producer wrote is still self-reported, because
    `grade_model_claim` never receives -- and cannot receive -- the hardware
    grade as an input."""
    record = _record(weights_digest="sha256:" + "ab" * 32)
    assert grade_model_claim(record, QUOTE_A) == MODEL_CLAIM_SELF_REPORTED


def test_model_claim_attested_only_when_recomputable_from_report_data():
    report_data_prefix = parse_tdx_quote(QUOTE_A).report_data[:32].hex()
    record = _record(weights_digest=f"sha256:{report_data_prefix}")
    assert grade_model_claim(record, QUOTE_A) == MODEL_CLAIM_ATTESTED


def test_model_claim_never_reads_the_advisory_binds_field():
    """The exact near-miss trace-spec#277 §6.1 documents: a first draft read
    `evidence.binds` to decide the grade, letting a producer raise its own claim by
    writing a string. Confirm this implementation is not fooled: declaring `binds`
    without earning it must still grade self-reported."""
    record = _record(weights_digest="sha256:" + "cd" * 32)
    record["runtime"]["evidence"]["binds"] = "weights-digest"  # producer's unearned advisory claim
    assert grade_model_claim(record, QUOTE_A) == MODEL_CLAIM_SELF_REPORTED


def test_citation_matches_rejects_wrong_digest_alg():
    record_bytes, reference = _cite(_record())
    reference["digest_alg"] = "SHA-1"
    assert citation_matches(record_bytes, reference) is False
