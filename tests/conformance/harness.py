#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Mesh-sidecar canonicalization conformance harness.

One-command, language-agnostic.  Point it at any implementation that speaks
the protocol below and it reports PASS/FAIL per vector.

Usage
-----
    # Run an external implementation against all committed vectors:
    python tests/conformance/harness.py verify-impl <command> [<vectors-dir>]

    # Run the Python oracle (acts as the reference implementation):
    python tests/conformance/harness.py oracle

    # Print the protocol specification:
    python tests/conformance/harness.py protocol

    # Generate a conforming stub (for testing the harness itself):
    python tests/conformance/harness.py generate-stub [<output-path>]

Example
-------
    python tests/conformance/harness.py verify-impl \
        'python tests/conformance/harness.py oracle'

Protocol (non-negotiable invariants)
--------------------------------------
D1 — RAW BYTES FROM DISK.
    The harness reads `input_bytes_hex` from each vector and decodes it to
    raw bytes.  It ASSERTS that those bytes equal the decoded hex (round-trip
    check).  It sends those EXACT bytes to the implementation's stdin.
    It NEVER calls json.loads(raw_bytes) + json.dumps(result) before sending.
    Defect this prevents: CPB#26-A — 1e2 becoming 100.0, changing the bytes
    under test and making the vector prove the opposite of its claim.

D2 — METADATA STRIPPED.
    For REJECT (must_fail) vectors the implementation receives ONLY the decoded
    input bytes.  The `must_fail`, `digest`, `failure_reason`, and all other
    harness-only fields are NEVER forwarded to the implementation.
    Defect this prevents: CPB#26-B — a self-certifying harness where an
    implementation passes by reading must_fail=true, not by rejecting the input.

D3 — EXIT-CODE CONTRACT SCOPED.
    The non-zero exit requirement is imposed ONLY on input-bearing REJECT
    vectors (must_fail=true AND input_bytes_hex present).  Vectors with no
    input (metadata-only, structural notes) are skipped, not erroneously
    counted as REJECT obligations.

See README.md for the full protocol and Rust socket documentation.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import unicodedata
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# jcs-n reference implementation (self-contained)
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
    """Parse JSON bytes, rejecting duplicate keys after escape processing + NFC."""
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


def compute_mesh_digest(raw_bytes: bytes) -> tuple[str, str]:
    """Parse raw_bytes and return (pre_image, digest) or raise on rejection."""
    parsed = _parse_with_dup_check(raw_bytes)
    normalized = _normalize(parsed)
    pre_image = _jcs_value(normalized)
    digest = hashlib.sha256(pre_image.encode('utf-8')).hexdigest()
    return pre_image, digest


# ---------------------------------------------------------------------------
# Oracle mode: act as the reference implementation for another harness
# ---------------------------------------------------------------------------

def _oracle_main() -> int:
    """Read raw JSON bytes from stdin; write {pre_image, digest} or exit 1."""
    raw = sys.stdin.buffer.read()
    try:
        pre_image, digest = compute_mesh_digest(raw)
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1
    print(json.dumps({'pre_image': pre_image, 'digest': digest}))
    return 0


# ---------------------------------------------------------------------------
# verify-impl mode
# ---------------------------------------------------------------------------

def _run_impl(command: str, raw_bytes: bytes) -> tuple[int, str, str]:
    """Invoke command with raw_bytes on stdin. Returns (exit_code, stdout, stderr)."""
    try:
        result = subprocess.run(
            command,
            shell=True,
            input=raw_bytes,
            capture_output=True,
            timeout=30,
        )
        return result.returncode, result.stdout.decode('utf-8', errors='replace'), \
               result.stderr.decode('utf-8', errors='replace')
    except subprocess.TimeoutExpired:
        return -1, '', 'timeout'


def verify_impl(command: str, root: Path) -> int:
    """Run command against all vectors in root. Returns exit code (0=all pass)."""
    passed = failed = skipped = 0
    failures: list[str] = []

    for vec_path in sorted(root.rglob('*.json')):
        try:
            raw_vec = vec_path.read_bytes()
            v = json.loads(raw_vec.decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue

        vid = v.get('id', str(vec_path.relative_to(root)))
        is_mutant = v.get('_is_mutant', False)

        # D3: skip vectors with no input
        if 'input_bytes_hex' not in v:
            skipped += 1
            continue

        # D1: decode hex to raw bytes; assert identity
        try:
            raw_input = bytes.fromhex(v['input_bytes_hex'])
        except ValueError as exc:
            failures.append(f'FAIL {vid}: input_bytes_hex is invalid hex: {exc}')
            failed += 1
            continue

        # D1 assertion: bytes we send MUST equal the bytes recorded on disk
        assert raw_input.hex() == v['input_bytes_hex'], (
            f'bytes-on-disk assertion failed for {vid}: '
            f'decoded hex round-trip mismatch (this is a harness bug, not an impl bug)'
        )

        # D2: for REJECT vectors — send ONLY the raw input bytes; never the full vector JSON
        is_reject = v.get('must_fail') is True

        if is_reject:
            # D2 enforced: the impl receives ONLY raw_input, never must_fail=true
            rc, stdout, stderr = _run_impl(command, raw_input)
            if rc == 0:
                failures.append(
                    f'FAIL {vid}: REJECT vector — command accepted invalid input (exit 0)\n'
                    f'  failure_reason: {v.get("failure_reason", "unspecified")}'
                )
                failed += 1
            else:
                passed += 1
            continue

        # PASS vector
        if v.get('_number_rule_pending') and v.get('digest') is None:
            print(f'  SKIP {vid}: number rule pending — digest=null', flush=True)
            skipped += 1
            continue

        rc, stdout, stderr = _run_impl(command, raw_input)
        if rc != 0:
            failures.append(
                f'FAIL {vid}: PASS vector — command exited {rc}\n'
                f'  stderr: {stderr.strip()!r}'
            )
            failed += 1
            continue

        if not stdout.strip():
            skipped += 1
            continue

        try:
            result = json.loads(stdout)
        except json.JSONDecodeError as exc:
            failures.append(f'FAIL {vid}: stdout is not valid JSON: {exc}')
            failed += 1
            continue

        got = result.get('digest', '')
        expected = v.get('digest', '')

        if expected and got != expected:
            label = 'MUTANT-detected' if is_mutant else 'FAIL'
            failures.append(
                f'{label} {vid}: digest mismatch\n'
                f'  expected: {expected}\n'
                f'  got:      {got}'
            )
            failed += 1
        else:
            passed += 1

    total = passed + failed + skipped
    print(f'\nharness verify-impl: {passed} pass, {skipped} skipped, {failed} FAILED  '
          f'(total vectors: {total})', flush=True)
    for f in failures:
        print(f, flush=True)
    return 1 if failures else 0


# ---------------------------------------------------------------------------
# generate-stub mode
# ---------------------------------------------------------------------------

_STUB = '''\
#!/usr/bin/env python3
# Mesh conformance stub generated by tests/conformance/harness.py.
# Speaks the conformance protocol: read JSON bytes from stdin; write
# {"pre_image": ..., "digest": ...} for PASS; exit 1 for REJECT inputs.
# Replace the oracle import with your own implementation.
import hashlib, json, sys, unicodedata
MAX = (1 << 53) - 1

def jcs_str(s):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"': out.append('\\\\"')
        elif ch == '\\\\': out.append('\\\\\\\\')
        elif o == 8: out.append('\\\\b')
        elif o == 9: out.append('\\\\t')
        elif o == 10: out.append('\\\\n')
        elif o == 12: out.append('\\\\f')
        elif o == 13: out.append('\\\\r')
        elif o < 32: out.append(f'\\\\u{o:04x}')
        else: out.append(ch)
    out.append('"'); return ''.join(out)

def jcs(v):
    if v is None: return 'null'
    if v is True: return 'true'
    if v is False: return 'false'
    if isinstance(v, int):
        if abs(v) > MAX: raise ValueError(f'unsafe int {v}')
        return str(v)
    if isinstance(v, float): raise TypeError(f'float: {v!r}')
    if isinstance(v, str): return jcs_str(v)
    if isinstance(v, list): return '[' + ','.join(jcs(x) for x in v) + ']'
    items = sorted(v.items(), key=lambda kv: kv[0].encode('utf-16-be'))
    return '{' + ','.join(jcs_str(k) + ':' + jcs(val) for k, val in items) + '}'

def normalize(v):
    if isinstance(v, dict):
        out = {}
        for k, val in v.items():
            nv = normalize(val)
            if nv is None or (isinstance(nv, (dict, list)) and not nv): continue
            out[k] = nv
        return out
    if isinstance(v, list): return [normalize(x) for x in v]
    return v

def parse(raw):
    seen = set()
    def pairs(p):
        out = {}
        for k, v in p:
            nfc = unicodedata.normalize('NFC', k)
            if nfc in seen: raise ValueError(f'dup key: {k!r}')
            seen.add(nfc); out[k] = v
        return out
    return json.loads(raw.decode(), object_pairs_hook=pairs)

raw = sys.stdin.buffer.read()
try:
    pre = jcs(normalize(parse(raw)))
    digest = hashlib.sha256(pre.encode()).hexdigest()
    print(json.dumps({"pre_image": pre, "digest": digest}))
except Exception as exc:
    print(f'error: {exc}', file=sys.stderr); sys.exit(1)
'''


def _generate_stub(output_path: Path) -> int:
    output_path.write_text(_STUB, encoding='utf-8')
    output_path.chmod(0o755)
    print(f'stub written to {output_path}')
    return 0


# ---------------------------------------------------------------------------
# Protocol documentation
# ---------------------------------------------------------------------------

_PROTOCOL = """\
Mesh Sidecar Canonicalization Conformance Protocol
====================================================

Algorithm
---------
The mesh sidecar computes a digest over OpenAI-shaped JSON objects (requests
and responses) via the following pipeline:

  1. PARSE raw JSON bytes, detecting duplicate keys after escape processing
     and NFC normalization of key strings.  Reject on duplicate.
  2. NORMALIZE: remove null-valued members and empty containers.
  3. JCS: RFC 8785 serialization (sorted by UTF-16BE key code units).
  4. DIGEST: SHA-256 of the UTF-8-encoded JCS string, hex-encoded.

Wire rule for numbers: ONLY plain integers in the range ±(2^53-1) are
accepted.  Scientific notation (1e2), decimal points (1.0), NaN, Infinity,
and -0 MUST cause rejection.

NFC departure: duplicate detection applies AFTER NFC normalization of key
strings (RFC 8785 §3.1 "preserve string data as is" is explicitly departed
from here).  A jcs-n-only implementation that does NOT apply NFC would miss
NFD/NFC-equivalent duplicate keys.

External command contract
--------------------------
The harness invokes the command once per vector with the raw input JSON bytes
on stdin.  The command MUST:

  For PASS vectors:
    - Exit 0.
    - Write to stdout: {"pre_image": "<utf8 string>", "digest": "<64 hex>"}
    - pre_image: the JCS-canonical UTF-8 string BEFORE hashing.
    - digest: 64 lowercase hex characters (SHA-256 of pre_image as UTF-8).

  For REJECT inputs (invalid JSON, duplicate keys, floats, etc.):
    - Exit non-zero (any non-zero status).
    - May write anything to stderr; it is not checked.

Harness non-negotiables
------------------------
D1. The harness reads input_bytes_hex from the vector file and decodes it
    to raw bytes.  Those EXACT bytes are sent to stdin.  The harness NEVER
    calls json.loads(raw_bytes) + json.dumps(result) before sending.

D2. must_fail, digest, failure_reason, and all other harness-only fields
    are NEVER forwarded to the implementation.  For REJECT vectors, the
    implementation receives ONLY the raw input bytes.  It cannot pass by
    reading must_fail=true; it must reject based on content.

D3. The non-zero exit requirement applies ONLY to vectors with both
    must_fail=true AND input_bytes_hex.

Rust socket (Phase 3)
---------------------
A Rust implementation can conform by reading stdin bytes and processing them:

  use std::io::Read;
  fn main() {
      let mut raw = Vec::new();
      std::io::stdin().read_to_end(&mut raw).unwrap();
      match compute_mesh_digest(&raw) {
          Ok((pre_image, digest)) => {
              println!("{{\\\"pre_image\\\":\\\"{pre_image}\\\",\\\"digest\\\":\\\"{digest}\\\"}}");
          }
          Err(e) => {
              eprintln!("error: {e}");
              std::process::exit(1);
          }
      }
  }

The `compute_mesh_digest` function implements:
  1. Parse JSON bytes, detecting duplicate keys (by NFC key comparison).
  2. Normalize: remove null/empty-container members.
  3. JCS: RFC 8785 canonical serialization.
  4. SHA-256 of the UTF-8-encoded JCS string, lowerhex.

Recommended crate: `serde_json` for parsing, `ryu-js` (boa-dev) for
number formatting, `sha2` for hashing.

For the JCS sort: sort object keys by their UTF-16BE byte sequence.
In Rust: key.encode_utf16().flat_map(|u| u.to_be_bytes()).collect::<Vec<_>>()

Test your implementation:
  python tests/conformance/harness.py verify-impl 'your-impl-binary'

Use as the reference-impl in your own harness:
  python tests/conformance/harness.py oracle
  # reads one vector's raw input from stdin; writes {pre_image, digest}; exits 1 on reject
"""


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    if not argv or argv[0] == 'protocol':
        print(_PROTOCOL)
        return 0

    if argv[0] == 'oracle':
        return _oracle_main()

    if argv[0] == 'generate-stub':
        out = Path(argv[1]) if len(argv) > 1 else Path('tests/conformance/stub_impl.py')
        return _generate_stub(out)

    if argv[0] == 'verify-impl':
        if len(argv) < 2:
            print('usage: harness.py verify-impl <command> [<vectors-dir>]', file=sys.stderr)
            return 2
        command = argv[1]
        root = Path(argv[2]) if len(argv) > 2 else Path(__file__).parent / 'vectors'
        if not root.is_dir():
            print(f'error: {root} is not a directory', file=sys.stderr)
            return 2
        return verify_impl(command, root)

    print(f'unknown subcommand: {argv[0]!r}', file=sys.stderr)
    print('usage: harness.py [protocol | oracle | generate-stub | verify-impl <cmd>]',
          file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
