#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""One-command vector generator for the mesh canonicalization conformance harness.

Run:
    python tests/conformance/generate_vectors.py

Generates:
    tests/conformance/vectors/pass/     -- PASS vectors (stable digest)
    tests/conformance/vectors/reject/   -- REJECT vectors (must_fail=true)
    tests/conformance/vectors/mutants/  -- Mutant vectors that MUST fail the harness

Harness invariants (see harness.py D1/D2/D3):
  D1 — input_bytes_hex records the EXACT bytes the harness will send.
       The generator derives input_bytes_hex from the canonical bytes BEFORE
       json.loads() -- it never re-serializes the input through json.dumps().
  D2 — must_fail and all harness-only fields are excluded when the harness
       sends input to the implementation.
  D3 — exit-code contract applies only to reject vectors with input_bytes_hex.

Mutants
-------
Each mutant has _is_mutant=true and exactly ONE property changed:
  - "digest-wrong": same input, one hex char of the digest changed.
  - "byte-flip": one byte of the input changed, digest unchanged (so mismatch).

A mutant MUST fail the harness when run against the reference oracle.  The
test_conformance_harness.py file verifies this.
"""
from __future__ import annotations

import hashlib
import json
import unicodedata
from pathlib import Path
from typing import Any

THIS_DIR = Path(__file__).resolve().parent
VECTORS_DIR = THIS_DIR / 'vectors'

# ---------------------------------------------------------------------------
# jcs-n oracle (same as harness.py — inlined for generator self-containment)
# ---------------------------------------------------------------------------

_MAX_SAFE_INT = (1 << 53) - 1


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
        if abs(v) > _MAX_SAFE_INT:
            raise ValueError(f'integer {v} outside ±{_MAX_SAFE_INT}')
        return str(v)
    if isinstance(v, float):
        raise TypeError(f'float not allowed in jcs-n: {v!r}')
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
            if isinstance(nv, (dict, list)) and not nv:
                continue
            out[k] = nv
        return out
    if isinstance(v, list):
        return [_normalize(x) for x in v]
    return v


def _parse_with_dup_check(raw: bytes) -> Any:
    def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        seen: set[str] = set()
        out: dict[str, Any] = {}
        for k, v in pairs:
            nfc_k = unicodedata.normalize('NFC', k)
            if nfc_k in seen:
                raise ValueError(f'duplicate key after NFC normalization: {k!r}')
            seen.add(nfc_k)
            out[k] = v
        return out

    return json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs)


def _digest_from_raw(raw_bytes: bytes) -> str:
    """Compute mesh digest from raw bytes. Raises on rejection."""
    parsed = _parse_with_dup_check(raw_bytes)
    normalized = _normalize(parsed)
    pre_image = _jcs_value(normalized)
    return hashlib.sha256(pre_image.encode('utf-8')).hexdigest()


def _raw_bytes_from_python_obj(obj: Any) -> bytes:
    """Produce canonical JSON bytes from a Python object (compact, no spaces).

    HARNESS GUARANTEE: the bytes produced here are the EXACT bytes stored in
    input_bytes_hex.  The harness sends these bytes verbatim to the implementation.
    It does NOT call json.loads(these_bytes) + json.dumps(result) before sending.
    """
    return json.dumps(obj, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


# ---------------------------------------------------------------------------
# Writer helpers
# ---------------------------------------------------------------------------

def _write(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(obj, indent=2, ensure_ascii=False) + '\n'
    path.write_text(text, encoding='utf-8')
    print(f'  wrote {path.relative_to(THIS_DIR)}')


def _pass_vector(id_: str, description: str, raw_bytes: bytes,
                 suite: str = 'pass', **extra: Any) -> dict[str, Any]:
    """Build a PASS vector from raw bytes.

    D1 guarantee: input_bytes_hex IS the hex of raw_bytes.  The generator
    never parses raw_bytes and re-serializes — it uses the bytes as-is.
    """
    digest = _digest_from_raw(raw_bytes)
    v: dict[str, Any] = {
        'id': id_,
        'description': description,
        'suite': suite,
        'input_bytes_hex': raw_bytes.hex(),
        'digest': digest,
        '_number_rule_pending': False,
    }
    v.update(extra)
    return v


def _reject_vector(id_: str, description: str, raw_bytes: bytes,
                   failure_reason: str, **extra: Any) -> dict[str, Any]:
    """Build a REJECT vector from raw bytes.

    D2 guarantee: must_fail is set in the VECTOR FILE but will be stripped
    by the harness before sending anything to the implementation.  The
    implementation receives only the decoded input_bytes_hex.
    """
    # Verify the oracle actually rejects these bytes
    try:
        _digest_from_raw(raw_bytes)
        print(f'  [BUG] reject case {id_!r} was NOT rejected by the oracle — fix the fixture')
    except (ValueError, TypeError, json.JSONDecodeError):
        pass  # expected

    v: dict[str, Any] = {
        'id': id_,
        'description': description,
        'suite': 'reject',
        'must_fail': True,
        'failure_reason': failure_reason,
        'input_bytes_hex': raw_bytes.hex(),
    }
    v.update(extra)
    return v


# ---------------------------------------------------------------------------
# 1. PASS vectors
# ---------------------------------------------------------------------------

def _build_pass_vectors() -> None:
    out = VECTORS_DIR / 'pass'

    # minimal chat request — no floats, stable digest
    req_bytes = _raw_bytes_from_python_obj({
        'model': 'hermes-2-pro-mistral-7b',
        'messages': [{'role': 'user', 'content': 'What is the capital of France?'}],
    })
    _write(out / 'request-no-params.json', _pass_vector(
        'request-no-params',
        (
            'PASS: minimal OpenAI chat request with no generation parameters. '
            'model + messages only; no floats. Digest is stable regardless of the number rule.'
        ),
        req_bytes,
        spec_ref='mesh-canonicalization-declaration §Rule 1',
        note='No floats. Digest is unconditionally stable.',
    ))

    # request with tool definitions — no floats, stable
    req_tools = _raw_bytes_from_python_obj({
        'model': 'hermes-2-pro-mistral-7b',
        'messages': [{'role': 'user', 'content': 'What files are in /?'}],
        'tools': [{
            'type': 'function',
            'function': {
                'name': 'list_files',
                'description': 'List files in a directory.',
                'parameters': {
                    'type': 'object',
                    'properties': {'path': {'type': 'string'}},
                    'required': ['path'],
                },
            },
        }],
        'tool_choice': 'auto',
    })
    _write(out / 'request-with-tools.json', _pass_vector(
        'request-with-tools',
        (
            'PASS: chat request with tool definitions. '
            'Tool parameters are strings/booleans — no floats. '
            'The jcs-n sort order: messages < model < tool_choice < tools.'
        ),
        req_tools,
        spec_ref='mesh-canonicalization-declaration §Rule 1',
    ))

    # simple text response — no floats, stable
    resp_bytes = _raw_bytes_from_python_obj({
        'id': 'chatcmpl-conf-001',
        'object': 'chat.completion',
        'created': 1724000500,
        'model': 'hermes-2-pro-mistral-7b',
        'choices': [{
            'index': 0,
            'message': {'role': 'assistant', 'content': 'Paris is the capital of France.'},
            'finish_reason': 'stop',
        }],
    })
    _write(out / 'response-text-basic.json', _pass_vector(
        'response-text-basic',
        (
            'PASS: minimal non-streaming chat.completion response. '
            'No floats; created is an integer (Unix timestamp). '
            'jcs-n sort order: choices < created < id < model < object.'
        ),
        resp_bytes,
        spec_ref='mesh-canonicalization-declaration §Rule 1',
    ))

    # response with null content — null removed by normalization
    resp_null = _raw_bytes_from_python_obj({
        'id': 'chatcmpl-conf-002',
        'object': 'chat.completion',
        'created': 1724000600,
        'model': 'hermes-2-pro-mistral-7b',
        'choices': [{
            'index': 0,
            'message': {
                'role': 'assistant',
                'content': None,
                'tool_calls': [{
                    'id': 'call_conf_aabb1122',
                    'type': 'function',
                    'function': {'name': 'get_weather', 'arguments': '{"city":"Rome"}'},
                }],
            },
            'finish_reason': 'tool_calls',
        }],
    })
    _write(out / 'response-null-content-normalized.json', _pass_vector(
        'response-null-content-normalized',
        (
            'PASS: response with content=null alongside tool_calls. '
            'jcs-n absent-field normalization removes null-valued members. '
            'The pre-image does NOT include the null content member; '
            'this confirms normalization fires before JCS serialization.'
        ),
        resp_null,
        spec_ref='mesh-canonicalization-declaration §Rule 1 (normalization)',
        note='content=null is stripped by normalization; pre_image excludes it.',
    ))

    # unicode content — verify JCS handles non-ASCII correctly
    resp_unicode = _raw_bytes_from_python_obj({
        'id': 'chatcmpl-conf-003',
        'object': 'chat.completion',
        'created': 1724000700,
        'model': 'hermes-2-pro-mistral-7b',
        'choices': [{
            'index': 0,
            'message': {'role': 'assistant', 'content': '42°C は Résumé の温度です。'},
            'finish_reason': 'stop',
        }],
    })
    _write(out / 'response-unicode-content.json', _pass_vector(
        'response-unicode-content',
        (
            'PASS: response with multi-script Unicode content '
            '(degree symbol, Japanese, French diacritics). '
            'jcs-n uses UTF-8 encoding; no characters require \\u escaping above U+001F. '
            'Ensures the implementation handles non-ASCII strings without corruption.'
        ),
        resp_unicode,
        spec_ref='mesh-canonicalization-declaration §Rule 1',
    ))


# ---------------------------------------------------------------------------
# 2. REJECT vectors
# ---------------------------------------------------------------------------

def _build_reject_vectors() -> None:
    out = VECTORS_DIR / 'reject'

    # D2 verification: these vectors have must_fail=true in the file.
    # The harness STRIPS this field before sending to the implementation.
    # The implementation must reject based on the CONTENT of the input,
    # not by reading must_fail from the protocol.

    # ---- duplicate key (literal) ----
    _write(out / 'dup-literal.json', _reject_vector(
        'dup-literal',
        (
            'REJECT: literal duplicate key. '
            '"key" appears twice in the same object. '
            'A conforming implementation MUST reject this input. '
            'If this passes, duplicate detection is broken at the most fundamental level.'
        ),
        b'{"key":"v1","key":"v2"}',
        failure_reason='duplicate_key_literal',
        spec_ref='mesh-canonicalization-declaration §Rule 3',
        note=(
            'Baseline reject case. The harness sends ONLY these bytes; '
            'the implementation never sees must_fail=true (harness D2).'
        ),
    ))

    # ---- duplicate key (escape-equivalent) ----
    # key == "key" after JSON escape processing.
    # Python json.loads with object_pairs_hook delivers post-escape keys,
    # so both "key" entries become the same string after parsing.
    dup_esc = b'{"\\u006b\\u0065\\u0079":"v1","key":"v2"}'
    _write(out / 'dup-escape-equiv.json', _reject_vector(
        'dup-escape-equiv',
        (
            'REJECT: escape-equivalent duplicate key. '
            r'"\\u006b\\u0065\\u0079" and "key" resolve to the same Unicode string '
            '"key" after JSON escape processing. '
            'Duplicate detection MUST happen after escape processing (post-parse). '
            'An implementation that compares raw bytes before escape processing '
            'would see different byte sequences and miss the duplicate.'
        ),
        dup_esc,
        failure_reason='duplicate_key_after_escape_processing',
        spec_ref='mesh-canonicalization-declaration §Rule 3',
        note=(
            'This is the defect-A inversion vector. '
            'A round-tripping harness calls json.loads(raw) which silently returns '
            'the last value for "key", discarding the duplicate. '
            'It then re-serializes to {"key":"v2"} — no duplicate — and the '
            'implementation accepts it, producing a FALSE PASS. '
            'This harness sends raw bytes; the implementation must detect the duplicate.'
        ),
    ))

    # ---- duplicate key (NFC-equivalent) ----
    # A (U+0041) + combining ring above (U+030A) = NFD form of Å
    # Å (U+00C5) = NFC precomposed Å
    # After NFC normalization both become U+00C5 — a duplicate.
    # Without NFC, JCS sorts them differently and they appear as distinct keys.
    nfc_bytes = ('{"' + 'Å' + '":"v1","' + 'Å' + '":"v2"}').encode('utf-8')
    _write(out / 'dup-nfc-nfd.json', _reject_vector(
        'dup-nfc-nfd',
        (
            'REJECT: NFC-equivalent duplicate key. '
            'U+0041 U+030A (A + combining ring above, NFD form of Å) and '
            'U+00C5 (Å precomposed, NFC) are the same character under NFC normalization. '
            'The mesh-canonicalization-declaration departs from RFC 8785 §3.1 by '
            'applying NFC to key strings before duplicate detection. '
            'A jcs-n-only implementation that does NOT apply NFC would sort these '
            'by UTF-16BE (U+0041 < U+00C5) and accept both as distinct keys, '
            'allowing an NFD twin to smuggle past the check.'
        ),
        nfc_bytes,
        failure_reason='duplicate_key_after_nfc_normalization',
        spec_ref='mesh-canonicalization-declaration §Rule 3 (NFC departure from RFC 8785 §3.1)',
        departure_from_rfc8785=(
            'RFC 8785 §3.1 states "preserve string data as is." '
            'The mesh declaration departs by applying NFC to key strings before '
            'duplicate detection. The JCS serialization step does NOT apply NFC; '
            'only duplicate detection uses NFC. Without this departure, an NFD twin '
            'of an NFC key evades the check.'
        ),
    ))

    # ---- float in field ----
    # Any float in a digest-bearing field must be rejected.
    _write(out / 'float-in-field.json', _reject_vector(
        'float-in-field',
        (
            'REJECT: floating-point number in a digest-bearing field. '
            'temperature=0.7 is a JSON number that Python parses as float. '
            'The wire rule allows only integers in ±(2^53-1); non-integer numbers '
            'MUST be rejected at the digest-boundary. '
            'Callers MUST convert floats to strings or integers at the call site; '
            'the algorithm does not accept them.'
        ),
        b'{"model":"hermes-2-pro-mistral-7b","temperature":0.7}',
        failure_reason='float_in_digest_field',
        spec_ref='mesh-canonicalization-declaration §Number rule',
        note=(
            'Representative of real goose requests that carry temperature as a float. '
            'A correct implementation rejects this before computing any digest.'
        ),
    ))

    # ---- scientific notation ----
    # 1e2 is valid JSON but not a valid integer wire token.
    # After Python json.loads: 100.0 (float). Both 1e2 and 100.0 are rejected.
    # This vector specifically tests the scientific-notation form.
    _write(out / 'float-scientific-notation.json', _reject_vector(
        'float-scientific-notation',
        (
            'REJECT: scientific-notation number (1e2). '
            '1e2 is a valid JSON number but not a valid integer wire token. '
            'The wire rule requires plain integer form: 0 or -?[1-9][0-9]*. '
            'After json.loads, 1e2 becomes Python float 100.0 — rejected for that reason. '
            'The raw bytes contain "1e2"; a round-tripping harness would send "100.0". '
            'Both are rejected by a conforming implementation, but for different byte inputs. '
            'This vector verifies the implementation rejects the LITERAL "1e2" form.'
        ),
        b'{"created":1e2}',
        failure_reason='non_integer_number_token',
        spec_ref='mesh-canonicalization-declaration §Number rule',
        note=(
            'Defect-A inversion case for numeric representation. '
            'A round-tripping harness parses 1e2 → float 100.0 → re-serializes → "100.0". '
            'A correct harness sends the raw b\'{"created":1e2}\' bytes. '
            'A correct impl rejects either form (both are non-integer), so the VERDICT '
            'is the same — but the BYTES UNDER TEST differ. '
            'This matters for Rust: serde_json may parse 1e2 as integer 100 (not float), '
            'which would change the verdict between correct and round-trip harnesses.'
        ),
    ))

    # ---- unsafe integer ----
    _write(out / 'unsafe-integer.json', _reject_vector(
        'unsafe-integer',
        (
            'REJECT: integer exceeding ±(2^53-1) = ±9007199254740991. '
            'JSON integers larger than 2^53-1 cannot be represented exactly as '
            'IEEE 754 float64 and MUST be rejected to prevent implementation-specific '
            'rounding differences from producing different pre-images.'
        ),
        b'{"big":9007199254740992}',
        failure_reason='integer_exceeds_max_safe',
        spec_ref='mesh-canonicalization-declaration §Number rule',
    ))


# ---------------------------------------------------------------------------
# 3. Mutant vectors (MUST fail the harness)
# ---------------------------------------------------------------------------

def _build_mutant_vectors() -> None:
    """Build committed mutants that MUST cause the harness to report FAIL.

    Mutants prove the harness is not a rubber-stamp.  Each mutant has exactly
    ONE property changed from a valid PASS vector.  When the harness runs the
    oracle against a mutant, it MUST report FAIL.

    The test_conformance_harness.py file verifies this.
    """
    out = VECTORS_DIR / 'mutants'

    req_bytes = _raw_bytes_from_python_obj({
        'model': 'hermes-2-pro-mistral-7b',
        'messages': [{'role': 'user', 'content': 'What is the capital of France?'}],
    })
    correct_digest = _digest_from_raw(req_bytes)

    # mutant-1: correct input, wrong digest (one hex char changed)
    wrong_digest = correct_digest[:-1] + ('0' if correct_digest[-1] != '0' else '1')
    _write(out / 'mutant-digest-wrong.json', {
        'id': 'mutant-digest-wrong',
        'description': (
            'MUTANT: correct input, wrong digest (one hex character changed). '
            'The implementation computes the correct digest but the pinned digest '
            'does not match. The harness MUST report FAIL. '
            'If the harness reports PASS on this vector, it is not checking the digest.'
        ),
        'suite': 'pass',
        '_is_mutant': True,
        '_mutation': 'last hex char of digest changed',
        'input_bytes_hex': req_bytes.hex(),
        'digest': wrong_digest,
    })

    # mutant-2: one character in a string VALUE changed; digest pinned to ORIGINAL.
    # We target a byte inside the "hermes-2-pro-mistral-7b" value string so the
    # modified bytes remain valid JSON (no structural character is affected).
    # The oracle computes a DIFFERENT digest from the modified bytes; the pinned
    # digest is the ORIGINAL — so the harness must report FAIL (digest mismatch).
    #
    # "hermes-2-pro-mistral-7b" starts at byte index 10 ("model":"...).
    # Change 'h' (0x68) -> 'H' (0x48) at index 10.
    flip_idx = 10  # byte index of 'h' in "hermes..."
    assert req_bytes[flip_idx] == ord('h'), (
        f'expected h at {flip_idx}, got {chr(req_bytes[flip_idx])!r} — fix the index'
    )
    flipped = bytearray(req_bytes)
    flipped[flip_idx] = ord('H')  # change 'h' to 'H' — valid JSON, different content
    flipped_bytes = bytes(flipped)
    flipped_digest = _digest_from_raw(flipped_bytes)
    assert flipped_digest != correct_digest, 'mutation did not change the digest — fix the mutant'

    _write(out / 'mutant-byte-flip.json', {
        'id': 'mutant-byte-flip',
        'description': (
            'MUTANT: one byte in a string value changed ('
            "'h' → 'H' in the model name), making the input valid JSON with "
            'a different content. The pinned digest is the ORIGINAL (unchanged) '
            'value; the oracle computes a DIFFERENT digest from the mutated bytes. '
            'The harness MUST report FAIL (digest mismatch). '
            'If the harness reports PASS, it is not verifying the digest.'
        ),
        'suite': 'pass',
        '_is_mutant': True,
        '_mutation': f"byte at index {flip_idx}: 'h' (0x68) changed to 'H' (0x48)",
        '_flip_index': flip_idx,
        '_original_byte_hex': f'{ord("h"):02x}',
        '_mutated_byte_hex': f'{ord("H"):02x}',
        '_actual_digest_of_mutated_bytes': flipped_digest,
        'input_bytes_hex': flipped_bytes.hex(),
        'digest': correct_digest,
    })

    # mutant-3: reject vector with must_fail REMOVED from the file
    # The harness should treat this as a PASS vector; the oracle will reject the input;
    # the harness will report FAIL (oracle exited 1 on a "pass" vector).
    # This proves the harness correctly enforces the must_fail/pass distinction.
    _write(out / 'mutant-reject-disguised-as-pass.json', {
        'id': 'mutant-reject-disguised-as-pass',
        'description': (
            'MUTANT: a REJECT input (duplicate key) presented WITHOUT must_fail=true. '
            'The harness treats it as a PASS vector. The oracle rejects the input '
            '(exits 1). The harness reports FAIL (oracle rejected a "pass" input). '
            'This verifies the harness correctly distinguishes pass from reject vectors.'
        ),
        'suite': 'pass',
        '_is_mutant': True,
        '_mutation': 'must_fail omitted; input is actually a reject vector',
        'input_bytes_hex': b'{"key":"v1","key":"v2"}'.hex(),
        'digest': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    })


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    print(f'Generating conformance vectors into {VECTORS_DIR.relative_to(THIS_DIR)}')
    print()

    print('=== 1. PASS vectors ===')
    _build_pass_vectors()
    print()

    print('=== 2. REJECT vectors ===')
    _build_reject_vectors()
    print()

    print('=== 3. Mutant vectors ===')
    _build_mutant_vectors()
    print()

    pass_vecs = list((VECTORS_DIR / 'pass').rglob('*.json'))
    reject_vecs = list((VECTORS_DIR / 'reject').rglob('*.json'))
    mutant_vecs = list((VECTORS_DIR / 'mutants').rglob('*.json'))

    print('=== Summary ===')
    print(f'  PASS vectors:    {len(pass_vecs)}')
    print(f'  REJECT vectors:  {len(reject_vecs)}')
    print(f'  Mutant vectors:  {len(mutant_vecs)}')
    print(f'  Total:           {len(pass_vecs) + len(reject_vecs) + len(mutant_vecs)}')
    print()
    print('Run: python tests/conformance/harness.py verify-impl '
          '"python tests/conformance/harness.py oracle"')
    return 0


if __name__ == '__main__':
    import sys
    sys.exit(main())
