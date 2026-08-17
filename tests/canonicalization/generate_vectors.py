#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""One-command canonicalization vector generator for capsule-emit-mesh.

Usage:
    python tests/canonicalization/generate_vectors.py

Generates:
    vectors/base/           -- repackaged from sibling repos (~2/3 of coverage)
    vectors/dup-key/        -- duplicate-key MUST-reject cases
    vectors/openai-shaped/  -- OpenAI request/response/SSE scaffolds
    vectors/response-digest/ -- two response-digest domains with declared transforms

Number-rule-pending cases:
    Any case whose digest depends on how floating-point values are represented
    carries "digest": null and "_number_rule_pending": true.  When the number
    rule is settled, update _stringify_floats_canonical() below and re-run this
    script.  No other file changes.  See README.md §"What changes when the number
    rule lands" for the complete list.

Harness contract:
    Feed input_bytes_hex (decoded to bytes) directly to the implementation.
    Never parse-and-reserialize.  See README.md §"Harness contract".
"""
from __future__ import annotations

import hashlib
import json
import shutil
import sys
import unicodedata
from datetime import timezone, datetime
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Paths
#
# The repo may live at <workspace>/capsule-emit-mesh (canonical checkout) or
# at <workspace>/_worktrees/capsule-emit-mesh/<branch> (worktree).  Walk up
# to find the workspace root (the directory that has agent-action-capsule as
# a sibling), rather than hard-coding a parent depth.
# ---------------------------------------------------------------------------
THIS_DIR = Path(__file__).resolve().parent
REPO_ROOT = THIS_DIR.parents[1]
VECTORS_OUT = THIS_DIR / "vectors"

_candidate = REPO_ROOT.parent
WORKSPACE_ROOT = REPO_ROOT.parent  # fallback
while _candidate != _candidate.parent:
    # Require agent-action-capsule to be a real git repo (has a .git directory,
    # not just a .git file as worktree refs have), to avoid matching _worktrees/.
    aac_candidate = _candidate / 'agent-action-capsule'
    if aac_candidate.exists() and (aac_candidate / '.git').is_dir():
        WORKSPACE_ROOT = _candidate
        break
    _candidate = _candidate.parent

SIBLING_AAC = WORKSPACE_ROOT / "agent-action-capsule" / "test-vectors"
SIBLING_CPB = WORKSPACE_ROOT / "scitt-payload-binding" / "vectors"


# ---------------------------------------------------------------------------
# Number-rule guard
#
# The float-to-string conversion rule is PENDING.  When it lands, replace the
# body of _stringify_floats_canonical with the declared rule.  The guard
# below controls which vectors get digest=null vs a real digest.
# ---------------------------------------------------------------------------
NUMBER_RULE_SETTLED = False  # flip to True when the rule lands


def _stringify_floats_canonical(value: Any) -> Any:
    """Pre-convert floats before jcs-n.

    CURRENT IMPLEMENTATION: Python repr(), which is the sidecar's existing
    behaviour.  PENDING: replace this with the declared rule once settled.
    """
    if isinstance(value, float):
        return repr(value)  # shortest round-trip decimal, CPython-specific
    if isinstance(value, dict):
        return {k: _stringify_floats_canonical(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_stringify_floats_canonical(v) for v in value]
    return value


def _contains_float(value: Any) -> bool:
    """Return True if value contains any Python float (after standard JSON parse)."""
    if isinstance(value, float):
        return True
    if isinstance(value, dict):
        return any(_contains_float(v) for v in value.values())
    if isinstance(value, list):
        return any(_contains_float(v) for v in value)
    return False


# ---------------------------------------------------------------------------
# Minimal jcs-n implementation (inlined for generator self-containment;
# authoritative impl is agent_action_capsule.canonical / cpb.canonicalize).
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
            raise UnsafeIntegerError(f'integer {v} outside ±{MAX_SAFE_INTEGER}')
        return str(v)
    if isinstance(v, float):
        raise FloatInDigestError('float in digest field')
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
    """jcs-n: normalize → JCS → SHA-256 → lowercase hex."""
    return hashlib.sha256(_jcs_value(_normalize(v)).encode('utf-8')).hexdigest()


def _mesh_digest(v: Any) -> str | None:
    """Mesh sidecar digest: _stringify_floats → jcs-n.

    Returns None if the value contains floats and NUMBER_RULE_SETTLED is False.
    """
    if _contains_float(v) and not NUMBER_RULE_SETTLED:
        return None
    return _jcs_n_digest(_stringify_floats_canonical(v))


# ---------------------------------------------------------------------------
# NFC duplicate detection
# ---------------------------------------------------------------------------

def _parse_with_dup_detection(raw: bytes) -> dict[str, Any]:
    """Parse JSON bytes, raising ValueError on duplicate keys (including
    NFC-equivalent duplicates — the mesh departure from RFC 8785 §3.1).

    Ordering: escape processing (by json.loads object_pairs_hook) then NFC
    then duplicate check.  This is the reference pipeline; implementations
    under test receive raw bytes and must implement equivalent logic.
    """
    seen: set[str] = set()

    def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for k, v in pairs:
            nfc_k = unicodedata.normalize('NFC', k)
            if nfc_k in seen:
                raise ValueError(
                    f'duplicate key after NFC normalization: {k!r} '
                    f'(NFC: {nfc_k!r})'
                )
            seen.add(nfc_k)
            out[k] = v
        return out

    return json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs)


# ---------------------------------------------------------------------------
# SSE helpers
# ---------------------------------------------------------------------------

def _reassemble_sse(sse_lines: list[str]) -> dict[str, Any]:
    """Fold OpenAI-style SSE chat.completion.chunk deltas into one object.

    Replicates capsule_sidecar.reassemble_streamed_response without importing
    the sidecar module directly (generator must be runnable without the full
    sidecar environment).
    """
    role = 'assistant'
    content_parts: list[str] = []
    tool_calls: dict[int, dict[str, Any]] = {}
    finish_reason = None
    resp_id = resp_model = resp_created = None

    for line in sse_lines:
        if not line.startswith('data: ') or line.strip() == 'data: [DONE]':
            continue
        chunk = json.loads(line[len('data: '):])
        resp_id = resp_id or chunk.get('id')
        resp_model = resp_model or chunk.get('model')
        resp_created = resp_created or chunk.get('created')
        choices = chunk.get('choices') or []
        if not choices:
            continue
        delta = choices[0].get('delta') or {}
        if delta.get('role'):
            role = delta['role']
        if delta.get('content'):
            content_parts.append(delta['content'])
        for tc in delta.get('tool_calls') or []:
            idx = tc.get('index', 0)
            slot = tool_calls.setdefault(
                idx,
                {'id': None, 'type': 'function', 'function': {'name': '', 'arguments': ''}},
            )
            if tc.get('id'):
                slot['id'] = tc['id']
            fn = tc.get('function') or {}
            if fn.get('name'):
                slot['function']['name'] += fn['name']
            if fn.get('arguments'):
                slot['function']['arguments'] += fn['arguments']
        if choices[0].get('finish_reason'):
            finish_reason = choices[0]['finish_reason']

    message: dict[str, Any] = {'role': role, 'content': ''.join(content_parts) or None}
    if tool_calls:
        message['tool_calls'] = [tool_calls[i] for i in sorted(tool_calls)]

    return {
        'id': resp_id,
        'object': 'chat.completion',
        'created': resp_created,
        'model': resp_model,
        'choices': [{'index': 0, 'message': message, 'finish_reason': finish_reason}],
    }


# ---------------------------------------------------------------------------
# Vector serialization helpers
# ---------------------------------------------------------------------------

def _write(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + '\n')
    print(f'  wrote {path.relative_to(THIS_DIR)}')


def _raw_bytes(s: str, encoding: str = 'utf-8') -> tuple[bytes, str]:
    """Return (raw_bytes, hex_string) for a JSON string literal."""
    b = s.encode(encoding)
    return b, b.hex()


# ---------------------------------------------------------------------------
# 1. Base repackaging
# ---------------------------------------------------------------------------

def _repackage_base() -> dict[str, Any]:
    """Copy vectors from sibling repos into vectors/base/ and return a manifest."""
    base_out = VECTORS_OUT / 'base'
    manifest_entries: list[dict[str, Any]] = []

    def _copy_tree(src: Path, dst: Path, source_repo: str, suite: str) -> None:
        if not src.exists():
            print(f'  [SKIP] {src} not found — is {source_repo} cloned alongside this repo?')
            return
        for f in sorted(src.rglob('*.json')):
            rel = f.relative_to(src)
            target = dst / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(f, target)
            manifest_entries.append({
                'suite': suite,
                'id': f.stem,
                'source_repo': source_repo,
                'source_path': str(f.relative_to(WORKSPACE_ROOT)),
                'dest_path': str(target.relative_to(VECTORS_OUT)),
            })

    _copy_tree(
        SIBLING_CPB / 'jcs-n' / 'kats',
        base_out / 'jcs-n' / 'kats',
        source_repo='scitt-payload-binding',
        suite='jcs-n-kats',
    )
    _copy_tree(
        SIBLING_CPB / 'jcs-n' / 'derived-id',
        base_out / 'jcs-n' / 'derived-id',
        source_repo='scitt-payload-binding',
        suite='jcs-n-derived-id',
    )
    _copy_tree(
        SIBLING_AAC,
        base_out / 'aac',
        source_repo='agent-action-capsule',
        suite='aac-verification',
    )

    manifest = {
        '_description': (
            'Repackaged base vectors.  These are read-only copies from sibling repos. '
            'Do not edit them here; update the source repo and re-run this generator.'
        ),
        'source_repos': {
            'scitt-payload-binding': str(SIBLING_CPB.relative_to(WORKSPACE_ROOT)),
            'agent-action-capsule': str(SIBLING_AAC.relative_to(WORKSPACE_ROOT)),
        },
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'vectors': manifest_entries,
    }
    _write(base_out / 'manifest.json', manifest)
    return manifest


# ---------------------------------------------------------------------------
# 2. Duplicate-key MUST-reject cases
# ---------------------------------------------------------------------------

def _build_dup_key_vectors() -> None:
    out = VECTORS_OUT / 'dup-key'

    def _dup(id_: str, description: str, raw_json: str, failure_reason: str,
              spec_note: str = '', departure_from_rfc8785: str = '') -> None:
        raw, hex_ = _raw_bytes(raw_json)
        v: dict[str, Any] = {
            'id': id_,
            'description': description,
            'spec_ref': 'mesh-canonicalization-declaration; see README §Rule 3',
            'must_fail': True,
            'failure_reason': failure_reason,
            'input_bytes_hex': hex_,
            '_raw_json_for_humans': raw_json,
        }
        if spec_note:
            v['spec_note'] = spec_note
        if departure_from_rfc8785:
            v['departure_from_rfc8785'] = departure_from_rfc8785
        try:
            _parse_with_dup_detection(raw)
            print(f'  [BUG] dup case {id_!r} was NOT rejected by reference parser')
        except (ValueError, json.JSONDecodeError):
            pass  # expected
        _write(out / f'{id_}.json', v)

    _dup(
        id_='dup-literal',
        description=(
            'MUST-FAIL: literal duplicate key. The same byte sequence "key" appears '
            'twice in the object. A conforming implementation MUST reject this input.'
        ),
        raw_json='{"key":"v1","key":"v2"}',
        failure_reason='duplicate_key_literal',
        spec_note=(
            'Baseline case: duplicate detection requires no special pipeline step. '
            'If an implementation passes this, its duplicate detection is broken '
            'at the most fundamental level.'
        ),
    )

    # k = k, e = e, y = y — after escape processing both keys are "key"
    _dup(
        id_='dup-escape-equiv',
        description=(
            'MUST-FAIL: escape-equivalent duplicate key. '
            r'"key" and "key" resolve to the same Unicode string '
            'after JSON escape processing. Duplicate detection MUST happen after '
            'escape processing (post-parse), not on raw bytes.'
        ),
        raw_json=r'{"key":"v1","key":"v2"}',
        failure_reason='duplicate_key_after_escape_processing',
        spec_note=(
            'An implementation that compares raw bytes before escape processing '
            r'would see "key" != "key" and miss the duplicate. '
            'The reference harness catches this via Python json.loads '
            'object_pairs_hook, which delivers post-escape keys.'
        ),
    )

    # NFC departure: A + combining ring above (NFD Å, U+0041 U+030A)
    #               vs precomposed Å (NFC, U+00C5)
    # After NFC normalization both become U+00C5; detected as duplicate.
    # Without NFC (RFC 8785 §3.1 "preserve as is") they are distinct keys.
    nfc_raw = '{"' + 'Å' + '":"v1","' + 'Å' + '":"v2"}'
    _dup(
        id_='dup-nfc-nfd',
        description=(
            'MUST-FAIL: NFC-equivalent duplicate key. '
            'U+0041 U+030A (A + combining ring above, NFD form of Å) and '
            'U+00C5 (Å precomposed, NFC form) are the same character under NFC. '
            'A conforming mesh-canonicalization implementation MUST apply NFC to '
            'keys before duplicate detection and MUST reject this input. '
            'THIS IS A DEPARTURE FROM RFC 8785 §3.1 ("preserve string data as is"): '
            'jcs-n does NOT apply NFC, and would NOT detect this as a duplicate. '
            'A jcs-n-only implementation would sort these keys by UTF-16 code units '
            '(U+0041 < U+00C5) and produce two distinct members — allowing an NFD '
            'twin to smuggle past the check.'
        ),
        raw_json=nfc_raw,
        failure_reason='duplicate_key_after_nfc_normalization',
        departure_from_rfc8785=(
            'RFC 8785 §3.1 states "preserve string data as is." '
            'This declaration departs from that by applying NFC normalization to '
            'key strings before duplicate detection. The JCS serialization step '
            'does NOT apply NFC; only the duplicate-detection step uses NFC. '
            'Without this departure, an NFD twin of an NFC key evades the check.'
        ),
    )

    # Duplicate detected before absent-field normalization removes the null member.
    # Ordering: dup-detect first, then normalize.
    _dup(
        id_='dup-before-normalization',
        description=(
            'MUST-FAIL: duplicate key where one value is null. '
            'Both "a" members are present; the first has value null and the second '
            'has value "v". Absent-field normalization (jcs-n step 1) would remove '
            'the null-valued member, but duplicate detection MUST happen before '
            'normalization so the duplicate is not silently resolved away.'
        ),
        raw_json='{"a":null,"a":"v"}',
        failure_reason='duplicate_key_before_normalization',
        spec_note=(
            'An implementation that normalizes before checking duplicates would '
            'remove the null "a" and proceed with {"a":"v"} — incorrectly accepting '
            'input that a correct implementation must reject. '
            'Duplicate detection is unconditional on the value of the duplicated member.'
        ),
    )

    # Pathological: escaped NFC-equivalent duplicate
    nfc_esc_raw = r'{"Å":"v1","Å":"v2"}'
    _dup(
        id_='dup-nfc-escaped',
        description=(
            'MUST-FAIL: NFC-equivalent duplicate, one key escaped. '
            r'"Å" is U+00C5 (NFC Å) via escape; "Å" is A + U+030A '
            '(NFD Å) via escape. After escape processing and NFC normalization, '
            'both resolve to U+00C5 — a duplicate. This combines the escape-equiv '
            'and NFC-departure cases into a single input to prevent an '
            'implementation from handling them separately and missing the composed case.'
        ),
        raw_json=nfc_esc_raw,
        failure_reason='duplicate_key_nfc_after_escape_processing',
        departure_from_rfc8785=(
            'Same RFC 8785 §3.1 departure as dup-nfc-nfd: NFC applied to post-escape '
            'key strings before duplicate detection.'
        ),
    )


# ---------------------------------------------------------------------------
# 3. SSE reassembly cases (no floats → full digests, stable)
# ---------------------------------------------------------------------------

def _sse_frames(base: dict[str, Any], deltas: list[dict[str, Any]]) -> list[str]:
    """Build raw SSE event strings from a base chunk template and deltas."""
    lines = []
    for delta, finish in deltas:
        chunk = {**base, 'choices': [{'index': 0, 'delta': delta, 'finish_reason': finish}]}
        lines.append(f'data: {json.dumps(chunk)}')
        lines.append('')
    lines.append('data: [DONE]')
    lines.append('')
    return lines


def _build_sse_vectors() -> None:
    out = VECTORS_OUT / 'openai-shaped' / 'sse'

    chunk_base = {
        'id': 'chatcmpl-sse-test-001',
        'object': 'chat.completion.chunk',
        'created': 1724000000,
        'model': 'hermes-2-pro-mistral-7b',
    }

    # ---- sse-text-basic ----
    text_deltas = [
        ({'role': 'assistant'}, None),
        ({'content': 'Hello'}, None),
        ({'content': ', world!'}, None),
        ({}, 'stop'),
    ]
    text_sse = _sse_frames(chunk_base, text_deltas)
    text_reassembled = _reassemble_sse(text_sse)
    text_digest = _mesh_digest(text_reassembled)

    _write(out / 'sse-text-basic.json', {
        'id': 'sse-text-basic',
        'description': (
            'SSE reassembly: simple text content delta sequence. '
            'The sidecar digests the REASSEMBLED chat.completion object, not '
            'the raw SSE bytes. This vector confirms that reassembly from '
            'incremental deltas produces the expected committed object.'
        ),
        'spec_ref': 'mesh-canonicalization-declaration; README §SSE reassembly cases',
        'suite': 'sse',
        '_number_rule_pending': False,
        'sse_raw_lines': text_sse,
        'reassembled': text_reassembled,
        'digest': text_digest,
        'note': (
            'The reassembled object has no floating-point values; digest is stable '
            'regardless of the number rule. `created` is an integer.'
        ),
    })

    # ---- sse-tool-call ----
    tool_deltas = [
        ({'role': 'assistant'}, None),
        ({'tool_calls': [{'index': 0, 'id': 'call_abc123', 'type': 'function',
                          'function': {'name': 'get_weather', 'arguments': ''}}]}, None),
        ({'tool_calls': [{'index': 0, 'function': {'arguments': '{"city":'}}]}, None),
        ({'tool_calls': [{'index': 0, 'function': {'arguments': '"Paris"}'}}]}, None),
        ({}, 'tool_calls'),
    ]
    tool_sse = _sse_frames(chunk_base, tool_deltas)
    tool_reassembled = _reassemble_sse(tool_sse)
    tool_digest = _mesh_digest(tool_reassembled)

    _write(out / 'sse-tool-call.json', {
        'id': 'sse-tool-call',
        'description': (
            'SSE reassembly: tool-call delta sequence. '
            'Incremental tool_calls deltas (name and arguments in separate chunks) '
            'are folded into a single tool_calls array entry. '
            'The upstream ID ("call_abc123") is carried through unchanged.'
        ),
        'spec_ref': 'mesh-canonicalization-declaration; README §SSE reassembly cases',
        'suite': 'sse',
        '_number_rule_pending': False,
        'sse_raw_lines': tool_sse,
        'reassembled': tool_reassembled,
        'digest': tool_digest,
        'note': (
            'Tool-call arguments are string-valued JSON; no floats present. '
            'When the upstream normalizer provides IDs (supported port path), '
            'the ID is in the raw stream and the sidecar does NOT mint a new one. '
            'The `tool_call_id_minted` transform would NOT fire for this input.'
        ),
    })

    # ---- sse-reassembly-stable ----
    # Show that streaming and non-streaming paths produce the same object + digest
    # for the same generation content.
    non_streaming_response = {
        'id': 'chatcmpl-sse-test-001',
        'object': 'chat.completion',
        'created': 1724000000,
        'model': 'hermes-2-pro-mistral-7b',
        'choices': [{
            'index': 0,
            'message': {'role': 'assistant', 'content': 'Hello, world!'},
            'finish_reason': 'stop',
        }],
    }
    non_streaming_digest = _mesh_digest(non_streaming_response)

    _write(out / 'sse-reassembly-stable.json', {
        'id': 'sse-reassembly-stable',
        'description': (
            'Streaming and non-streaming paths produce identical digest for the '
            'same generation. The SSE reassembly of the text-basic stream and the '
            'equivalent non-streaming response object must yield the same digest. '
            'This is the invariant that makes response_digest meaningful for '
            'streaming clients: the capsule commits to a value a non-streaming '
            'client could independently reproduce.'
        ),
        'spec_ref': 'mesh-canonicalization-declaration; README §SSE reassembly cases',
        'suite': 'sse',
        '_number_rule_pending': False,
        'streaming_reassembled': text_reassembled,
        'streaming_digest': text_digest,
        'non_streaming_response': non_streaming_response,
        'non_streaming_digest': non_streaming_digest,
        'invariant_holds': text_digest == non_streaming_digest,
        'note': (
            'If invariant_holds is False, there is a bug in either the SSE '
            'reassembly function or the test fixture construction. '
            'A correct generator always produces True here.'
        ),
    })
    if text_digest != non_streaming_digest:
        print(f'  [BUG] sse-reassembly-stable: invariant FAILED — digests differ')


# ---------------------------------------------------------------------------
# 4. Response-digest domains (float-free inputs → stable digests)
# ---------------------------------------------------------------------------

def _build_response_digest_vectors() -> None:
    out = VECTORS_OUT / 'response-digest'

    # Shared base response (no floats; tool_call IDs from upstream normalizer)
    raw_upstream_text = {
        'id': 'chatcmpl-resp-001',
        'object': 'chat.completion',
        'created': 1724000100,
        'model': 'hermes-2-pro-mistral-7b',
        'choices': [{
            'index': 0,
            'message': {'role': 'assistant', 'content': 'The temperature is 22°C.'},
            'finish_reason': 'stop',
        }],
    }

    raw_upstream_tool = {
        'id': 'chatcmpl-resp-002',
        'object': 'chat.completion',
        'created': 1724000200,
        'model': 'hermes-2-pro-mistral-7b',
        'choices': [{
            'index': 0,
            'message': {
                'role': 'assistant',
                'content': 'Let me check the weather.',
                'tool_calls': [{'id': 'call_xyz789', 'type': 'function',
                                'function': {'name': 'get_weather',
                                             'arguments': '{"city":"Berlin"}'}}],
            },
            'finish_reason': 'tool_calls',
        }],
    }

    # ---- domain-no-transform ----
    resp_digest = _mesh_digest(raw_upstream_text)
    forwarded_copy_digest = _mesh_digest(raw_upstream_text)

    _write(out / 'domain-no-transform.json', {
        'id': 'domain-no-transform',
        'description': (
            'Two-domain declaration — no transforms. The upstream response is '
            'returned to the calling agent byte-for-byte unchanged. '
            'forwarded_copy.transforms is empty; forwarded_copy.digest equals '
            'response_digest. The capsule still emits both fields explicitly '
            'so a verifier can distinguish "unchanged" from "not reported".'
        ),
        'spec_ref': 'mesh-canonicalization-declaration; README §Response-digest domains',
        'suite': 'response-digest',
        '_number_rule_pending': False,
        'raw_upstream': raw_upstream_text,
        'forwarded_copy': raw_upstream_text,
        'transforms': [],
        'upstream_tool_call_ids': [],
        'response_digest': resp_digest,
        'forwarded_copy_digest': forwarded_copy_digest,
        'invariant': {
            'transforms_empty_implies_equal_digests': resp_digest == forwarded_copy_digest,
        },
    })

    # ---- domain-content-dropped ----
    # Tool response with content AND tool_calls — content dropped for client compat.
    raw_with_content = {
        'id': 'chatcmpl-resp-003',
        'object': 'chat.completion',
        'created': 1724000300,
        'model': 'hermes-2-pro-mistral-7b',
        'choices': [{
            'index': 0,
            'message': {
                'role': 'assistant',
                'content': 'I will call get_weather.',  # spurious content
                'tool_calls': [{'id': 'call_abc456', 'type': 'function',
                                'function': {'name': 'get_weather',
                                             'arguments': '{"city":"Tokyo"}'}}],
            },
            'finish_reason': 'tool_calls',
        }],
    }
    import copy
    forwarded_content_dropped = copy.deepcopy(raw_with_content)
    forwarded_content_dropped['choices'][0]['message']['content'] = None

    raw_digest_cd = _mesh_digest(raw_with_content)
    fwd_digest_cd = _mesh_digest(forwarded_content_dropped)

    _write(out / 'domain-content-dropped.json', {
        'id': 'domain-content-dropped',
        'description': (
            'Two-domain declaration — content_dropped_with_tool_calls transform. '
            'The raw upstream response has both content and tool_calls. '
            'The forwarded copy has content set to null (removed). '
            'response_digest attests the raw bytes; forwarded_copy.digest attests '
            'the client-compatible bytes. The transforms list documents the change '
            'so a verifier can reason about the seam. '
            'The null content is removed by jcs-n absent-field normalization in the '
            'forwarded_copy digest pre-image, while the raw upstream pre-image '
            'retains it (as the string value, before _stringify_floats).'
        ),
        'spec_ref': 'mesh-canonicalization-declaration; README §Response-digest domains',
        'suite': 'response-digest',
        '_number_rule_pending': False,
        'raw_upstream': raw_with_content,
        'forwarded_copy': forwarded_content_dropped,
        'transforms': ['content_dropped_with_tool_calls'],
        'upstream_tool_call_ids': ['call_abc456'],
        'response_digest': raw_digest_cd,
        'forwarded_copy_digest': fwd_digest_cd,
        'invariant': {
            'non_empty_transforms_implies_unequal_digests': raw_digest_cd != fwd_digest_cd,
        },
    })

    # ---- domain-id-minted ----
    # Tool calls without upstream IDs (local-model-only path); sidecar mints them.
    raw_no_ids = {
        'id': 'chatcmpl-resp-004',
        'object': 'chat.completion',
        'created': 1724000400,
        'model': 'hermes-2-pro-mistral-7b',
        'choices': [{
            'index': 0,
            'message': {
                'role': 'assistant',
                'content': None,
                'tool_calls': [{'type': 'function',
                                'function': {'name': 'list_files',
                                             'arguments': '{"path":"/"}'}}],
            },
            'finish_reason': 'tool_calls',
        }],
    }
    forwarded_minted = copy.deepcopy(raw_no_ids)
    forwarded_minted['choices'][0]['message']['tool_calls'][0]['id'] = 'call_minted_aabbcc112233'

    raw_digest_mi = _mesh_digest(raw_no_ids)
    fwd_digest_mi = _mesh_digest(forwarded_minted)

    _write(out / 'domain-id-minted.json', {
        'id': 'domain-id-minted',
        'description': (
            'Two-domain declaration — tool_call_id_minted transform. '
            'The raw upstream response has no tool_call id (--local-model-only path; '
            'the mesh-llm host normalizer is not active). '
            'The sidecar mints an id for client compatibility. '
            'response_digest attests the raw bytes (no id field); '
            'forwarded_copy.digest attests the minted-id bytes. '
            'upstream_tool_call_ids is empty (no ids came from upstream).'
        ),
        'spec_ref': 'mesh-canonicalization-declaration; README §Response-digest domains',
        'suite': 'response-digest',
        '_number_rule_pending': False,
        'raw_upstream': raw_no_ids,
        'forwarded_copy': forwarded_minted,
        'transforms': ['tool_call_id_minted'],
        'upstream_tool_call_ids': [],
        'response_digest': raw_digest_mi,
        'forwarded_copy_digest': fwd_digest_mi,
        'invariant': {
            'non_empty_transforms_implies_unequal_digests': raw_digest_mi != fwd_digest_mi,
        },
        'note': (
            'The minted id in forwarded_copy is a synthetic fixture value. '
            'In production the sidecar uses uuid.uuid4().hex[:24], which varies per run. '
            'A verifier must compute forwarded_copy.digest from the forwarded bytes '
            'it actually received, not from this fixture value.'
        ),
    })


# ---------------------------------------------------------------------------
# 5. OpenAI-shaped request/response scaffolds
# ---------------------------------------------------------------------------

def _build_openai_shaped_vectors() -> None:
    req_out = VECTORS_OUT / 'openai-shaped' / 'request'
    resp_out = VECTORS_OUT / 'openai-shaped' / 'response'

    def _req_vector(id_: str, description: str, request: dict[str, Any],
                    note: str = '') -> None:
        pending = _contains_float(request) and not NUMBER_RULE_SETTLED
        digest = _mesh_digest(request)
        v: dict[str, Any] = {
            'id': id_,
            'description': description,
            'spec_ref': 'mesh-canonicalization-declaration; README §Rule 1',
            'suite': 'openai-shaped-request',
            '_number_rule_pending': pending,
            'input': request,
            'input_bytes_hex': json.dumps(request, separators=(',', ':'),
                                          ensure_ascii=False).encode('utf-8').hex(),
            'digest': digest,
        }
        if note:
            v['note'] = note
        if pending:
            v['_pending_note'] = (
                'Digest is null because this request contains floating-point values '
                '(temperature, top_p, etc.) and the float-to-string conversion rule '
                'is not yet settled. Re-run generate_vectors.py after the rule lands.'
            )
        _write(req_out / f'{id_}.json', v)

    # Request with no floats — stable digest
    _req_vector(
        id_='request-no-params',
        description=(
            'OpenAI chat request with no generation parameters (no floats). '
            'A minimal request: model + messages only. '
            'Digest is stable regardless of the number rule.'
        ),
        request={
            'model': 'hermes-2-pro-mistral-7b',
            'messages': [{'role': 'user', 'content': 'What is the capital of France?'}],
        },
        note='No floats present. This vector has a stable digest.',
    )

    # Request WITH floats — pending
    _req_vector(
        id_='request-with-temperature',
        description=(
            'OpenAI chat request with temperature (float). '
            'PENDING NUMBER RULE: temperature=0.7 is a Python float; '
            '_stringify_floats_canonical() converts it to repr(0.7)="0.7" before jcs-n. '
            'If the declared rule uses a different representation, the digest changes. '
            'digest=null until the rule is settled.'
        ),
        request={
            'model': 'hermes-2-pro-mistral-7b',
            'messages': [{'role': 'user', 'content': 'Summarize this document.'}],
            'temperature': 0.7,
            'top_p': 1.0,
            'max_tokens': 512,
        },
        note=(
            'Representative of real goose requests to mesh-llm. '
            'temperature and top_p are JSON numbers → Python floats after parse. '
            'The full set of float fields the sidecar encounters: '
            'temperature, top_p, presence_penalty, frequency_penalty.'
        ),
    )

    # Request with tool_use — string args, no floats
    _req_vector(
        id_='request-with-tools',
        description=(
            'OpenAI chat request with tool definitions (no floats in tool spec). '
            'Tool definitions use string/integer/boolean parameters; no floats. '
            'Digest is stable regardless of the number rule.'
        ),
        request={
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
        },
        note='Tool spec has no floats. If temperature were added it would become pending.',
    )

    def _resp_vector(id_: str, description: str, response: dict[str, Any],
                     note: str = '') -> None:
        pending = _contains_float(response) and not NUMBER_RULE_SETTLED
        digest = _mesh_digest(response)
        v: dict[str, Any] = {
            'id': id_,
            'description': description,
            'spec_ref': 'mesh-canonicalization-declaration; README §Rule 1',
            'suite': 'openai-shaped-response',
            '_number_rule_pending': pending,
            'input': response,
            'input_bytes_hex': json.dumps(response, separators=(',', ':'),
                                          ensure_ascii=False).encode('utf-8').hex(),
            'digest': digest,
        }
        if note:
            v['note'] = note
        _write(resp_out / f'{id_}.json', v)

    # Simple text response — no floats, stable
    _resp_vector(
        id_='response-text-basic',
        description=(
            'Non-streaming chat.completion response: simple text content. '
            'No floating-point values. Digest is stable regardless of the number rule.'
        ),
        response={
            'id': 'chatcmpl-oai-001',
            'object': 'chat.completion',
            'created': 1724000500,
            'model': 'hermes-2-pro-mistral-7b',
            'choices': [{
                'index': 0,
                'message': {'role': 'assistant', 'content': 'Paris is the capital of France.'},
                'finish_reason': 'stop',
            }],
        },
    )

    # Tool-call response — stable
    _resp_vector(
        id_='response-tool-call',
        description=(
            'Non-streaming chat.completion response: tool_call result. '
            'No floating-point values. Digest is stable regardless of the number rule.'
        ),
        response={
            'id': 'chatcmpl-oai-002',
            'object': 'chat.completion',
            'created': 1724000600,
            'model': 'hermes-2-pro-mistral-7b',
            'choices': [{
                'index': 0,
                'message': {
                    'role': 'assistant',
                    'content': None,
                    'tool_calls': [{
                        'id': 'call_oai_aabb1122',
                        'type': 'function',
                        'function': {'name': 'get_weather', 'arguments': '{"city":"Rome"}'},
                    }],
                },
                'finish_reason': 'tool_calls',
            }],
        },
        note=(
            'content=null is removed by jcs-n absent-field normalization. '
            'The digest pre-image does not include the null content member.'
        ),
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    print(f'Generating canonicalization vectors into {VECTORS_OUT.relative_to(REPO_ROOT)}')
    print()

    print('=== 1. Base repackaging ===')
    manifest = _repackage_base()
    print(f'  {len(manifest["vectors"])} base vectors indexed')
    print()

    print('=== 2. Duplicate-key MUST-reject cases ===')
    _build_dup_key_vectors()
    print()

    print('=== 3. SSE reassembly cases ===')
    _build_sse_vectors()
    print()

    print('=== 4. Response-digest domain cases ===')
    _build_response_digest_vectors()
    print()

    print('=== 5. OpenAI-shaped scaffolds ===')
    _build_openai_shaped_vectors()
    print()

    # Summary
    all_vectors = sorted(VECTORS_OUT.rglob('*.json'))
    pending = [f for f in all_vectors if '"_number_rule_pending": true' in f.read_text()]
    stable = [f for f in all_vectors if f.name != 'manifest.json'
              and '"_number_rule_pending": true' not in f.read_text()]

    print('=== Summary ===')
    print(f'  Total vector files:        {len(all_vectors)}')
    print(f'  Stable (full digest):      {len(stable)}')
    print(f'  Pending number rule:       {len(pending)}')
    if pending:
        print('  Pending files:')
        for f in pending:
            print(f'    {f.relative_to(THIS_DIR)}')
    print()
    print('Done.  See tests/canonicalization/README.md for the harness contract.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
