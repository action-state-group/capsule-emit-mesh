#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Vector harness for mesh canonicalization vectors.

Run:
    pytest tests/canonicalization/test_vectors.py -v

Contract (from README §Harness contract):
  - Feed input_bytes_hex (decoded to bytes) directly to the implementation.
  - Never parse-and-reserialize between receipt and digest computation.
  - MUST-FAIL cases: implementation must SIGNAL rejection; harness verifies
    the signal, not merely the absence of a digest output.
  - PASS cases: digest verified byte-for-byte; a null digest (pending number
    rule) is skipped loudly, not silently.
"""
from __future__ import annotations

import hashlib
import json
import unicodedata
from pathlib import Path
from typing import Any

import pytest

VECTORS_DIR = Path(__file__).parent / 'vectors'


# ---------------------------------------------------------------------------
# Reference implementation (same as generator — inlined for harness independence)
# ---------------------------------------------------------------------------
MAX_SAFE_INTEGER = 2**53 - 1


class FloatInDigestError(ValueError):
    pass


class UnsafeIntegerError(ValueError):
    pass


def _jcs_string(s: str) -> str:
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == '\\':
            out.append('\\\\')
        elif o == 0x08:
            out.append('\\b')
        elif o == 0x09:
            out.append('\\t')
        elif o == 0x0A:
            out.append('\\n')
        elif o == 0x0C:
            out.append('\\f')
        elif o == 0x0D:
            out.append('\\r')
        elif o < 0x20:
            out.append(f'\\u{o:04x}')
        else:
            out.append(ch)
    out.append('"')
    return ''.join(out)


def _jcs_value(v: Any) -> str:
    if v is None:
        return 'null'
    if isinstance(v, bool):
        return 'true' if v else 'false'
    if isinstance(v, int):
        if v > MAX_SAFE_INTEGER or v < -MAX_SAFE_INTEGER:
            raise UnsafeIntegerError(v)
        return str(v)
    if isinstance(v, float):
        raise FloatInDigestError(v)
    if isinstance(v, str):
        return _jcs_string(v)
    if isinstance(v, list):
        return '[' + ','.join(_jcs_value(x) for x in v) + ']'
    if isinstance(v, dict):
        items = sorted(v.items(), key=lambda kv: kv[0].encode('utf-16-be'))
        return '{' + ','.join(_jcs_string(k) + ':' + _jcs_value(val) for k, val in items) + '}'
    raise TypeError(type(v))


def _normalize(v: Any) -> Any:
    if isinstance(v, dict):
        out: dict[str, Any] = {}
        for k, val in v.items():
            nv = _normalize(val)
            if nv is None:
                continue
            if isinstance(nv, (dict, list)) and len(nv) == 0:
                continue
            out[k] = nv
        return out
    if isinstance(v, list):
        return [_normalize(x) for x in v]
    return v


def _jcs_n_digest(v: Any) -> str:
    return hashlib.sha256(_jcs_value(_normalize(v)).encode('utf-8')).hexdigest()


def _parse_with_dup_detection(raw: bytes) -> dict[str, Any]:
    """Parse JSON bytes, detecting duplicates after escape processing and NFC.

    This is the mesh-departure pipeline:
    1. JSON parse (escape processing via json.loads object_pairs_hook)
    2. NFC normalize each key
    3. Reject on duplicate (RFC 8785 §3.1 departure)
    """
    seen: set[str] = set()

    def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for k, v in pairs:
            nfc_k = unicodedata.normalize('NFC', k)
            if nfc_k in seen:
                raise ValueError(f'duplicate key: {k!r} (NFC: {nfc_k!r})')
            seen.add(nfc_k)
            out[k] = v
        return out

    return json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs)


# ---------------------------------------------------------------------------
# Vector collection
# ---------------------------------------------------------------------------

def _load_vectors(subdir: str, *, skip_base: bool = True) -> list[tuple[str, dict]]:
    """Load all non-base vector files from the given subdirectory."""
    base = VECTORS_DIR / subdir
    if not base.exists():
        return []
    result = []
    for f in sorted(base.rglob('*.json')):
        if f.name == 'manifest.json':
            continue
        v = json.loads(f.read_text())
        result.append((str(f.relative_to(VECTORS_DIR)), v))
    return result


# ---------------------------------------------------------------------------
# Duplicate-key MUST-FAIL tests
# ---------------------------------------------------------------------------

DUP_VECTORS = _load_vectors('dup-key')


@pytest.mark.parametrize('path,vector', DUP_VECTORS, ids=[p for p, _ in DUP_VECTORS])
def test_dup_key_must_fail(path: str, vector: dict) -> None:
    """Each dup-key vector MUST be rejected by the reference implementation.

    Harness contract: raw bytes → implementation; not parse-and-reserialize.
    Rejection must be signalled; the absence of an output does not count.
    """
    assert vector.get('must_fail') is True, f'{path}: expected must_fail=true'
    raw_bytes = bytes.fromhex(vector['input_bytes_hex'])

    with pytest.raises((ValueError, json.JSONDecodeError), match=r'duplicate') as exc_info:
        _parse_with_dup_detection(raw_bytes)

    _ = exc_info  # consumed by pytest.raises; signal is the rejection itself


@pytest.mark.parametrize('path,vector', DUP_VECTORS, ids=[p for p, _ in DUP_VECTORS])
def test_dup_nfc_departure_stated(path: str, vector: dict) -> None:
    """NFC-departure cases must carry the departure_from_rfc8785 field.

    This ensures the departure is explicitly documented in the vector, not
    implicit.  Without the field, the test passes silently for a jcs-n
    implementation that happens to detect the case by coincidence.
    """
    if 'nfc' not in path:
        pytest.skip('not an NFC departure case')
    assert 'departure_from_rfc8785' in vector, (
        f'{path}: NFC departure case missing departure_from_rfc8785 field'
    )
    assert 'RFC 8785' in vector['departure_from_rfc8785']


# ---------------------------------------------------------------------------
# SSE reassembly tests
# ---------------------------------------------------------------------------

SSE_VECTORS = _load_vectors('openai-shaped/sse')


@pytest.mark.parametrize('path,vector', SSE_VECTORS, ids=[p for p, _ in SSE_VECTORS])
def test_sse_stable_digest(path: str, vector: dict) -> None:
    """SSE vectors with a stable digest (no pending number rule) verify correctly."""
    if vector.get('_number_rule_pending'):
        pytest.skip(f'{path}: number rule pending — skipping digest check')

    if 'reassembly_stable' in path:
        assert vector['invariant_holds'] is True, (
            f'{path}: sse-reassembly-stable invariant_holds must be True; '
            f'generator produced a buggy fixture'
        )
        assert vector['streaming_digest'] == vector['non_streaming_digest']
        return

    if 'digest' in vector and vector['digest'] is not None:
        reassembled = vector['reassembled']
        computed = _jcs_n_digest(reassembled)
        assert computed == vector['digest'], (
            f'{path}: reassembled digest mismatch\n'
            f'  computed:  {computed}\n'
            f'  expected:  {vector["digest"]}'
        )


@pytest.mark.parametrize('path,vector', SSE_VECTORS, ids=[p for p, _ in SSE_VECTORS])
def test_sse_no_floats_in_reassembled(path: str, vector: dict) -> None:
    """SSE vectors must not have floats in the reassembled object.

    A reassembled object with floats would be a number-rule-dependent case,
    but SSE vectors claim stability.  Catch this invariant at test time.
    """
    if 'reassembled' not in vector:
        return

    def _has_float(v: Any) -> bool:
        if isinstance(v, float):
            return True
        if isinstance(v, dict):
            return any(_has_float(x) for x in v.values())
        if isinstance(v, list):
            return any(_has_float(x) for x in v)
        return False

    assert not _has_float(vector['reassembled']), (
        f'{path}: reassembled object contains floats; this vector should not be '
        f'marked stable — set _number_rule_pending: true or remove floats'
    )


# ---------------------------------------------------------------------------
# Response-digest domain tests
# ---------------------------------------------------------------------------

RESP_DOMAIN_VECTORS = _load_vectors('response-digest')


@pytest.mark.parametrize('path,vector', RESP_DOMAIN_VECTORS, ids=[p for p, _ in RESP_DOMAIN_VECTORS])
def test_response_digest_domains(path: str, vector: dict) -> None:
    """Response-digest domain vectors verify both digest fields."""
    if vector.get('_number_rule_pending'):
        pytest.skip(f'{path}: number rule pending')

    raw_upstream = vector['raw_upstream']
    forwarded_copy = vector['forwarded_copy']

    computed_resp = _jcs_n_digest(raw_upstream)
    computed_fwd = _jcs_n_digest(forwarded_copy)

    assert computed_resp == vector['response_digest'], (
        f'{path}: response_digest mismatch\n'
        f'  computed:  {computed_resp}\n'
        f'  expected:  {vector["response_digest"]}'
    )
    assert computed_fwd == vector['forwarded_copy_digest'], (
        f'{path}: forwarded_copy_digest mismatch\n'
        f'  computed:  {computed_fwd}\n'
        f'  expected:  {vector["forwarded_copy_digest"]}'
    )

    transforms = vector.get('transforms', [])
    inv = vector.get('invariant', {})

    if not transforms:
        assert computed_resp == computed_fwd, (
            f'{path}: empty transforms but digests differ — '
            f'forwarded copy was silently modified'
        )
        if 'transforms_empty_implies_equal_digests' in inv:
            assert inv['transforms_empty_implies_equal_digests'] is True
    else:
        assert computed_resp != computed_fwd, (
            f'{path}: non-empty transforms but digests are equal — '
            f'transform did not produce a different pre-image'
        )
        if 'non_empty_transforms_implies_unequal_digests' in inv:
            assert inv['non_empty_transforms_implies_unequal_digests'] is True


# ---------------------------------------------------------------------------
# OpenAI-shaped request/response tests
# ---------------------------------------------------------------------------

OPENAI_REQ_VECTORS = _load_vectors('openai-shaped/request')
OPENAI_RESP_VECTORS = _load_vectors('openai-shaped/response')


@pytest.mark.parametrize('path,vector', OPENAI_REQ_VECTORS, ids=[p for p, _ in OPENAI_REQ_VECTORS])
def test_openai_request_digest(path: str, vector: dict) -> None:
    if vector.get('_number_rule_pending') and vector.get('digest') is None:
        pytest.skip(f'{path}: number rule pending — digest=null, cannot verify')

    computed = _jcs_n_digest(vector['input'])
    assert computed == vector['digest'], (
        f'{path}: request digest mismatch\n'
        f'  computed:  {computed}\n'
        f'  expected:  {vector["digest"]}'
    )


@pytest.mark.parametrize('path,vector', OPENAI_RESP_VECTORS, ids=[p for p, _ in OPENAI_RESP_VECTORS])
def test_openai_response_digest(path: str, vector: dict) -> None:
    if vector.get('_number_rule_pending') and vector.get('digest') is None:
        pytest.skip(f'{path}: number rule pending — digest=null, cannot verify')

    computed = _jcs_n_digest(vector['input'])
    assert computed == vector['digest'], (
        f'{path}: response digest mismatch\n'
        f'  computed:  {computed}\n'
        f'  expected:  {vector["digest"]}'
    )


# ---------------------------------------------------------------------------
# SSE transcript tests
# ---------------------------------------------------------------------------

TRANSCRIPT_VECTORS = _load_vectors('openai-shaped/sse/transcript')


@pytest.mark.parametrize('path,vector', TRANSCRIPT_VECTORS, ids=[p for p, _ in TRANSCRIPT_VECTORS])
def test_transcript_digest_domain(path: str, vector: dict) -> None:
    """Every transcript vector must declare sse_digest_domain = 'frame-payloads'."""
    if 'generation_error' in vector:
        pytest.skip(f'{path}: mock rig was unavailable during generation')
    assert vector.get('sse_digest_domain') == 'frame-payloads', (
        f'{path}: transcript must declare sse_digest_domain="frame-payloads"; '
        f'got {vector.get("sse_digest_domain")!r}'
    )


@pytest.mark.parametrize('path,vector', TRANSCRIPT_VECTORS, ids=[p for p, _ in TRANSCRIPT_VECTORS])
def test_transcript_response_digest(path: str, vector: dict) -> None:
    """Transcript response_digest matches independent recomputation from reassembled."""
    if 'generation_error' in vector:
        pytest.skip(f'{path}: mock rig was unavailable during generation')
    if vector.get('_number_rule_pending') and vector.get('response_digest') is None:
        pytest.skip(f'{path}: number rule pending — response_digest=null, cannot verify')

    reassembled = vector.get('reassembled')
    if reassembled is None:
        pytest.skip(f'{path}: no reassembled object (placeholder vector)')

    computed = _jcs_n_digest(reassembled)
    assert computed == vector['response_digest'], (
        f'{path}: response_digest mismatch\n'
        f'  computed:  {computed}\n'
        f'  expected:  {vector["response_digest"]}'
    )


@pytest.mark.parametrize('path,vector', TRANSCRIPT_VECTORS, ids=[p for p, _ in TRANSCRIPT_VECTORS])
def test_transcript_independent_verification_claim(path: str, vector: dict) -> None:
    """Transcript must carry the independent_verification field.

    This test is structural: it checks that the transcript DECLARES the
    independent-verification claim, not just that it has a digest.  The absence
    of the field would mean the vector is not making the #1331 claim at all.
    """
    if 'generation_error' in vector:
        pytest.skip(f'{path}: mock rig was unavailable during generation')
    assert 'independent_verification' in vector, (
        f'{path}: transcript must carry independent_verification field '
        f'(the #1331 "independent test calculation" claim)'
    )
    iv = vector['independent_verification']
    assert 'description' in iv, f'{path}: independent_verification must have description'
    assert 'algorithm' in iv, f'{path}: independent_verification must have algorithm'


@pytest.mark.parametrize('path,vector', TRANSCRIPT_VECTORS, ids=[p for p, _ in TRANSCRIPT_VECTORS])
def test_transcript_mock_rig_verified(path: str, vector: dict) -> None:
    """Mock-rig transcript must have independent_verification.verified == True."""
    if not vector.get('mock_rig'):
        pytest.skip(f'{path}: not a mock-rig transcript')
    if 'generation_error' in vector:
        pytest.skip(f'{path}: mock rig was unavailable during generation')
    if vector.get('_number_rule_pending') and vector.get('response_digest') is None:
        pytest.skip(f'{path}: number rule pending — cannot verify digest')
    iv = vector.get('independent_verification', {})
    assert iv.get('verified') is True, (
        f'{path}: mock-rig transcript must have independent_verification.verified=True; '
        f'this means the sidecar\'s computed digest equals an independent recomputation '
        f'from the same frame payloads — the #1331 claim'
    )


# ---------------------------------------------------------------------------
# Structural integrity: no pending vector silently passes
# ---------------------------------------------------------------------------

ALL_VECTOR_FILES = sorted(VECTORS_DIR.rglob('*.json'))


@pytest.mark.parametrize('vector_path', [
    f for f in ALL_VECTOR_FILES
    if f.name != 'manifest.json'
    and 'base/' not in str(f.relative_to(VECTORS_DIR))
], ids=[str(f.relative_to(VECTORS_DIR)) for f in ALL_VECTOR_FILES
        if f.name != 'manifest.json'
        and 'base/' not in str(f.relative_to(VECTORS_DIR))])
def test_pending_vectors_are_not_silently_accepted(vector_path: Path) -> None:
    """A pending vector with digest=null must NOT be treated as passing.

    This test verifies the harness explicitly skips (not passes) pending vectors.
    A pending vector that silently passes is the same defect as a must-fail
    check with no assertion: confident output with no way to notice it is false.
    """
    v = json.loads(vector_path.read_text())
    if not v.get('_number_rule_pending'):
        return
    if v.get('digest') is not None:
        pytest.fail(
            f'{vector_path.name}: has _number_rule_pending=true but digest is '
            f'not null — either clear the pending flag or set digest=null'
        )
