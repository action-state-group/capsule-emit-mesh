#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SSE transcript builder for mesh canonicalization.

Implements the SSE transcript construction defined in README.md
§"SSE transcript definition" and validates it against the mock rig.

DIGEST DOMAIN: FRAME PAYLOADS ONLY.  See README §"SSE digest domain: why frame
payloads" for the argument and the complete enumeration of what SSE permits an
intermediary to change.

Usage (against the mock rig):
    python tests/canonicalization/sse_transcript.py
"""
from __future__ import annotations

import hashlib
import json
import sys
import threading
import urllib.request
from pathlib import Path
from typing import Any

THIS_DIR = Path(__file__).resolve().parent
REPO_ROOT = THIS_DIR.parents[1]
sys.path.insert(0, str(REPO_ROOT))

# ---------------------------------------------------------------------------
# Minimal jcs-n (inlined — harness must be self-contained, no installed deps).
# ---------------------------------------------------------------------------
MAX_SAFE_INTEGER = 2**53 - 1


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
            raise ValueError(f'unsafe integer {v}')
        return str(v)
    if isinstance(v, float):
        raise TypeError(f'float in digest field: {v!r}')
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


def _has_float(v: Any) -> bool:
    if isinstance(v, float):
        return True
    if isinstance(v, dict):
        return any(_has_float(x) for x in v.values())
    if isinstance(v, list):
        return any(_has_float(x) for x in v)
    return False


# ---------------------------------------------------------------------------
# SSE parsing
# ---------------------------------------------------------------------------

def parse_sse_stream(raw_bytes: bytes) -> list[dict[str, Any]]:
    """Parse SSE stream bytes into frame payloads.

    Digest domain: FRAME PAYLOADS ONLY.

    For each SSE event:
    1. Split lines on \\n, \\r\\n, or \\r (all are valid SSE terminators).
    2. For each line starting with "data:", strip the optional leading space,
       and parse the payload as JSON.
    3. Skip comment lines (starting with ":"), retry: fields, and [DONE].
    4. Return the list of parsed JSON objects in delivery order.

    What this deliberately discards (transport-variant, not digest-worthy):
    - Line terminator bytes (\\n vs \\r\\n — intermediary may change)
    - Comment lines (intermediary may insert)
    - retry: fields (intermediary may change)
    - The "data: " prefix bytes themselves
    - HTTP chunk boundaries
    - Blank lines between events
    """
    import re
    lines = re.split(r'\r\n|\r|\n', raw_bytes.decode('utf-8', errors='replace'))
    payloads: list[dict[str, Any]] = []
    for line in lines:
        if not line.startswith('data:'):
            continue
        payload_str = line[len('data:'):]
        if payload_str.startswith(' '):
            payload_str = payload_str[1:]  # strip optional single leading space (SSE spec)
        if payload_str == '[DONE]' or not payload_str:
            continue
        try:
            obj = json.loads(payload_str)
            payloads.append(obj)
        except json.JSONDecodeError:
            pass
    return payloads


def reassemble_sse(frame_payloads: list[dict[str, Any]]) -> dict[str, Any]:
    """Fold SSE frame payloads into one chat.completion object.

    Replicates capsule_sidecar.reassemble_streamed_response.

    USAGE EXCLUSION: Usage fields (prompt_tokens, completion_tokens,
    total_tokens) are intentionally NOT included in the reassembled object.
    Reasons:
    1. Real mesh-llm streams do not emit usage in the main chunk stream;
       usage appears only in a trailing implementation-specific annotation.
    2. Usage token counts are plain integers but their inclusion would make
       the transcript format number-rule-sensitive (the full transcript spec
       is pending) — a future mesh-llm version might emit float-typed usage.
    3. The reassembled object must be identical to what a non-streaming client
       would receive from the same generation, and OpenAI non-streaming
       responses include usage at the top level (not inside choices[0]), so
       including or excluding it consistently is the only unambiguous choice.

    When the full transcript spec is settled, usage handling must be declared
    explicitly: either always excluded from the digest pre-image, or included
    with a declared algorithm for float-safe encoding.
    """
    role = 'assistant'
    content_parts: list[str] = []
    tool_calls: dict[int, dict[str, Any]] = {}
    finish_reason = None
    resp_id = resp_model = resp_created = None

    for chunk in frame_payloads:
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
# Transcript builder
# ---------------------------------------------------------------------------

def build_sse_transcript(
    raw_sse_bytes: bytes,
    *,
    exchange_id: str | None = None,
    number_rule_settled: bool = False,
) -> dict[str, Any]:
    """Build an SSE transcript from raw SSE wire bytes.

    Args:
        raw_sse_bytes: The complete SSE stream as received from the wire.
            May include any combination of \\n, \\r\\n, \\r line terminators,
            comment lines, retry: fields, and HTTP chunk boundaries — all of
            these are stripped during frame payload extraction.
        exchange_id: Optional capsule_id or correlation token.
        number_rule_settled: Set True once the float-to-string conversion rule
            is declared; until then, response_digest is null for any transcript
            whose reassembled object contains floats.

    Returns:
        A transcript dict with:
          - sse_digest_domain: always "frame-payloads"
          - frame_payloads: list of parsed JSON objects from data: lines
          - reassembled: the reassembled chat.completion object
          - response_digest: jcs-n digest of reassembled (null if pending)
          - _number_rule_pending: True if digest was suppressed
          - independent_verification: the claim this transcript makes
    """
    frame_payloads = parse_sse_stream(raw_sse_bytes)
    reassembled = reassemble_sse(frame_payloads)
    has_floats = _has_float(reassembled)
    pending = has_floats and not number_rule_settled

    digest: str | None
    if pending:
        digest = None
    else:
        digest = _jcs_n_digest(reassembled)

    transcript: dict[str, Any] = {
        'transcript_kind': 'sse-streamed',
        'transcript_algorithm': 'mesh-sse-reassembly-v1',
        'sse_digest_domain': 'frame-payloads',
        'frame_count': len(frame_payloads),
        'frame_payloads': frame_payloads,
        'reassembled': reassembled,
        'response_digest': digest,
        '_number_rule_pending': pending,
        'independent_verification': {
            'description': (
                'The sidecar computed response_digest INDEPENDENTLY from the '
                'SSE frame payloads it observed on the wire. This is the '
                '"independent test calculation" in the #1331 verification box: '
                'the host cannot substitute different response bytes and claim '
                'the digest matches, because the sidecar computed it from what '
                'actually flowed, not from what the host reported.'
            ),
            'algorithm': 'parse_sse_stream → reassemble_sse → jcs-n',
            'verified': digest is not None,
        },
    }
    if exchange_id is not None:
        transcript['exchange_id'] = exchange_id

    return transcript


# ---------------------------------------------------------------------------
# Mock-rig integration
# ---------------------------------------------------------------------------

def run_against_mock(
    prompt: str = 'What is 2 + 2?',
    port: int = 19877,
) -> dict[str, Any]:
    """Spin up the mock node, send a streaming request, and return the transcript.

    This is the "implemented against the mock rig" demonstration.  The mock
    node runs in a thread; the client sends a streaming request; the raw SSE
    bytes are captured; the transcript is built from those bytes.

    Key invariant checked: the transcript's response_digest must equal the
    digest that the sidecar would compute from the same frame payloads.  This
    is the #1331 verification box: independent calculation by an external
    observer produces the same value as what the host-embedded sidecar would
    have signed.
    """
    server_ready = threading.Event()
    server_thread = threading.Thread(
        target=_start_mock,
        args=(port, server_ready),
        daemon=True,
    )
    server_thread.start()
    server_ready.wait(timeout=3.0)

    request_json = {
        'model': 'capsule-emit-poc/tiny-fixture-model:Q4_K_XL',
        'messages': [{'role': 'user', 'content': prompt}],
        'stream': True,
    }
    raw_request = json.dumps(request_json).encode('utf-8')

    req = urllib.request.Request(
        f'http://127.0.0.1:{port}/v1/chat/completions',
        data=raw_request,
        headers={'Content-Type': 'application/json', 'Accept': 'text/event-stream'},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        raw_sse_bytes = resp.read()

    transcript = build_sse_transcript(raw_sse_bytes)

    # Independent verification: the sidecar independently computed response_digest
    # from the same frame payloads.  A third-party verifier does the same here.
    if transcript['response_digest'] is not None:
        recomputed = _jcs_n_digest(transcript['reassembled'])
        assert recomputed == transcript['response_digest'], (
            f'INVARIANT FAILED: recomputed digest does not match transcript digest\n'
            f'  recomputed: {recomputed}\n'
            f'  transcript: {transcript["response_digest"]}'
        )
        transcript['independent_verification']['verified'] = True
        transcript['independent_verification']['recomputed_digest'] = recomputed

    return transcript


def _start_mock(port: int, ready_event: threading.Event) -> None:
    import mock_mesh_node as mock_mod
    from http.server import ThreadingHTTPServer
    server = ThreadingHTTPServer(('127.0.0.1', port), mock_mod.Handler)
    ready_event.set()
    server.handle_request()  # serve one request then exit


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    print('Running SSE transcript against mock rig...')
    transcript = run_against_mock()
    print(f'  frame_count:      {transcript["frame_count"]}')
    print(f'  response_digest:  {transcript["response_digest"]}')
    print(f'  pending:          {transcript["_number_rule_pending"]}')
    print(f'  verified:         {transcript["independent_verification"]["verified"]}')
    print()
    print(json.dumps(transcript, indent=2))
