# Mesh Canonicalization Conformance Harness

Language-agnostic conformance harness for the mesh-LLM canonicalization algorithm.
An implementation under test reads raw JSON from stdin and writes a structured JSON
result to stdout; the harness drives it against committed fixtures and reports pass/fail.

## Quick start

```bash
# Self-test: run the oracle against all fixtures
python3 tests/conformance/harness.py verify-impl \
    "python3 tests/conformance/harness.py oracle" \
    tests/conformance/vectors

# Expected output:
# harness verify-impl: 11 pass, 0 skipped, 3 FAILED  (total vectors: 14)
# MUTANT-detected mutant-byte-flip: ...
# MUTANT-detected mutant-digest-wrong: ...
# FAIL mutant-reject-disguised-as-pass: ...
```

The harness exits non-zero when any non-mutant vector fails.
Mutant failures are reported separately and counted as expected; PASS vectors
and REJECT vectors must all succeed.

## Defects this harness was built to avoid

Two defects were identified in an earlier CPB vector harness (CPB#26):

**CPB#26-A — round-trip changes bytes.**  
The old harness called `json.loads(raw) + json.dumps(result)` before sending the
input to the implementation under test.  This transformed `1e2` → `100.0` and
removed escape-equivalent duplicate keys silently.  The bytes the implementation
received differed from the bytes on disk — so a must-fail vector could pass even
though the implementation never saw the original input.

*Fix:* D1 — `input_bytes_hex` stores the exact bytes on disk as hex.  The harness
decodes with `bytes.fromhex()` and includes an assertion that the decoded hex
equals the original.  No `json.loads`/`json.dumps` round-trip touches the bytes
before they are sent to the implementation.

**CPB#26-B — self-certifying must-fail.**  
The old harness sent the full vector JSON (including `must_fail: true`) to the
implementation.  A naive or compliant-looking implementation could read the flag
and exit 1 without inspecting the input at all.  A harness pass told the Rust
vendor nothing about actual rejection behavior.

*Fix:* D2 — for REJECT vectors the harness sends ONLY the raw input bytes.  The
implementation never sees `must_fail`, `failure_reason`, or any other harness field.
It must reject by content or not at all.

The pytest suite (`tests/test_conformance_harness.py`) contains inversion tests that
demonstrate each defect being present (RED) and then absent (GREEN).

## Vector structure

```
tests/conformance/vectors/
  pass/       # inputs the algorithm must accept; digest is pinned
  reject/     # inputs the algorithm must reject; must_fail=true; no digest
  mutants/    # malformed vectors; harness must FAIL for every mutant
```

Every PASS vector:
```json
{
  "id":             "request-no-params",
  "description":    "...",
  "input_bytes_hex": "<hex of exact bytes on disk>",
  "digest":         "<sha256 hex of the jcs-n pre-image>"
}
```

Every REJECT vector (D2: `must_fail` never forwarded to the impl):
```json
{
  "id":             "dup-literal",
  "must_fail":      true,
  "failure_reason": "duplicate_key_literal",
  "input_bytes_hex": "<hex of the invalid input>"
}
```

## Regenerating fixtures

```bash
python3 tests/conformance/generate_vectors.py
```

Generates all fixtures from Python source; does not read existing fixture files.
Safe to re-run; overwrites all files in `vectors/`.

## Subcommands

| Command | Description |
|---------|-------------|
| `verify-impl <cmd> <vector-dir>` | Run `<cmd>` against all vectors in `<vector-dir>` |
| `oracle` | Reference Python implementation (reads stdin, writes stdout) |
| `generate-stub` | Print a starter implementation stub |
| `protocol` | Print the CLI protocol spec |

## CLI protocol (Rust / other language socket)

An implementation speaks the protocol over stdin/stdout:

**Input** (written to the process stdin): raw JSON bytes of the input object.

**Output** for an accepted input (exit 0):
```json
{"pre_image": "<utf-8 string>", "digest": "<sha256 hex>"}
```

**Output** for a rejected input (exit 1 or other non-zero):
Any output on stderr is captured; stdout is ignored.

### Rust socket example

```rust
use std::io::{self, Read, Write};
use serde_json::Value;

fn main() {
    let mut raw = Vec::new();
    io::stdin().read_to_end(&mut raw).unwrap();

    match mesh_canonicalize(&raw) {
        Ok((pre_image, digest)) => {
            let out = serde_json::json!({"pre_image": pre_image, "digest": digest});
            println!("{}", out);
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("error: {}", e);
            std::process::exit(1);
        }
    }
}
```

Run against all fixtures:
```bash
python3 tests/conformance/harness.py verify-impl \
    "./target/debug/mesh-oracle" \
    tests/conformance/vectors
```

### Exit-code contract scope (D3)

Only vectors with `must_fail=true` AND `input_bytes_hex` require exit non-zero.
Pure schema/structural failures without `input_bytes_hex` are excluded from the
exit-code contract; the harness skips them rather than asserting on their exit code.

## Algorithm overview

The mesh canonicalization algorithm (see `harness.py:compute_mesh_digest`):

1. **Parse** JSON bytes with per-object-level duplicate detection.  
   Duplicate keys (literal or escape-equivalent) → reject.  
   NFC-equivalent keys (NFD vs NFC) → reject after NFC normalization.

2. **Normalize** (jcs-n): remove null-valued members; remove empty objects and arrays;
   apply recursively until stable.

3. **JCS serialization** (RFC 8785): sort keys by UTF-16BE code unit sequence;
   no extra whitespace; specific string escape rules.

4. **SHA-256** of the UTF-8 JCS bytes → 64-character hex digest.

**Wire rule for numbers**: only plain integers in ±(2^53 − 1) are accepted.
Floats, scientific notation (`1e2`), NaN, Infinity, and `-0` cause rejection.
