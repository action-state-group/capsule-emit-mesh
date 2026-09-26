# capsule-producer test fixtures

## `python_produced_noncanonical_envelope.hex`

A **golden vector**: a COSE_Sign1 (CBOR tag 18) **producer envelope** emitted by
the PYTHON reference (`scitt_cose.cose_sign1.sign_sign1`, via
`tests/scripts/produce_python_envelope.py`), carrying its **non-canonical**
protected-header key order **(3, 4, 1)** — content_type (3), kid (4), alg (1) —
because the reference appends the forced `alg` (label 1) LAST. RFC 9052 §9
requires canonical order (1, 3, 4); this insertion order is a §9 violation, and
the point of the fixture is to prove the Rust door ACCEPTS it as-received.

This is stored (not regenerated at test time) deliberately: a
stored insertion-order envelope that Rust verifies is a golden vector for
as-received behavior, and it stays useful even if the Python reference later
moves to canonical order.

The Rust test `rust_verifies_a_python_produced_noncanonical_envelope`
(`tests/cross_language_conformance.rs`) LOADS this file and asserts
`verify_signed_statement` ACCEPTS it. It does NOT invoke Python.

### Known values (needed to verify / regenerate)

- Ed25519 signing seed (private key, 32 bytes): `11` repeated 32× (`0x11 * 32`)
- Envelope payload = digest signed over (32 bytes): `22` repeated 32× (`0x22 * 32`)
- kid = raw Ed25519 public key (32 bytes):
  `d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737`
- protected-header key order on the wire: `[3, 4, 1]` (non-canonical)

The verifying key the Rust test uses is derived from the seed above; the kid in
the envelope equals that raw public key.

### Regenerating

Run once and overwrite the `.hex` (this is the documented regenerator; the test
does NOT call it):

```
AAC_VENV_PYTHON tests/scripts/produce_python_envelope.py \
  1111111111111111111111111111111111111111111111111111111111111111 \
  2222222222222222222222222222222222222222222222222222222222222222 \
  /tmp/py_envelope.bin
xxd -p /tmp/py_envelope.bin | tr -d '\n' > tests/fixtures/python_produced_noncanonical_envelope.hex
```

Requires a Python env with `scitt_cose`, `agent_action_capsule`, `cbor2`, and
`cryptography` installed.
