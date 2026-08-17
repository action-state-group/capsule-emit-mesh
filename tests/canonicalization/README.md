# Canonicalization vector suite — capsule-emit-mesh

Conformance vector suite for the mesh-llm sidecar's canonicalization declaration.
The declaration extends jcs-n (draft-mih-sokolov-scitt-payload-binding-00 §3.1)
with three mesh-specific rules; see §Scope below.

## Regenerating

```
cd tests/canonicalization
python generate_vectors.py
```

One command.  The generator computes every digest from its inputs; nothing is
hand-authored.  A rule change is a re-run, not a rewrite.

### Status — SCAFFOLD (2026-08-17)

Number-rule declaration text and the -0 KAT are PENDING Anton's reply /
the 2026-08-19 session.  Until then:

* Cases whose digest depends on how floats are represented carry
  `"digest": null` and `"_number_rule_pending": true`.
* All structural, duplicate-key, SSE-reassembly, and float-free cases carry
  full computed digests and are stable.

---

## Scope

### What this declaration governs

The sidecar digests two objects per exchange:

| Field | Pre-image |
|---|---|
| `response_digest` | `_stringify_floats(raw_upstream_response)` → jcs-n |
| `forwarded_copy.digest` | `_stringify_floats(forwarded_copy_object)` → jcs-n |

Both use the same pipeline: `_stringify_floats` converts every Python `float`
to `repr(float)` (exact round-trip decimal), then jcs-n canonicalizes the
result.  The `_number_rule_pending` marker applies to any case that contains
floating-point values, because `repr()` is the CURRENT implementation but the
DECLARATION text is pending.

### Three mesh-specific rules (beyond bare jcs-n)

**Rule 1 — float pre-conversion.**  Before jcs-n, every JSON floating-point
number is replaced by its exact decimal-string representation.  This converts
OpenAI's float fields (temperature, top_p, penalties, logprobs) into strings
that jcs-n can handle without violating its float-in-digest-field prohibition.
**The exact conversion rule is pending (see `_number_rule_pending`).**

**Rule 2 — NFC key normalization for duplicate detection (DEPARTURE from
RFC 8785 §3.1).**  Before duplicate-key detection, every object key string is
NFC-normalized.  This is an explicit DEPARTURE from RFC 8785 §3.1, which
states "preserve string data as is."  Without it, an NFD twin of an NFC key
passes through undetected:

```
{"Å": "v1", "Å": "v2"}
```

`Å` is A + combining-ring-above (NFD).  `Å` is Å (NFC precomposed).
NFC-normalizing both produces `Å` twice — detected as a duplicate.
Without NFC, they are distinct keys at the JCS sort step, and the duplicate
survives into the canonical form.

**The NFC normalization applies ONLY to the duplicate-detection step.**  The
JCS serialization step (RFC 8785) does NOT apply NFC; keys are serialized from
their post-parse (possibly NFD) Unicode strings.  So a single-key input whose
key is NFD-encoded produces an identical digest to jcs-n.

**Rule 3 — duplicate-key rejection ordering.**  Rejection must happen:
1. After escape processing (post-parse Unicode code points, not raw escape bytes).
2. After NFC normalization (Rule 2 above).
3. Before absent-field normalization.

The harness feeds raw bytes to the implementation under test.  It never
parse-and-reserializes.

---

## Vector layout

```
vectors/
  base/
    manifest.json          Index of repackaged source vectors from sibling repos
    jcs-n/kats/            KATs from scitt-payload-binding/vectors/jcs-n/kats/
    jcs-n/derived-id/      Derived-id cases from scitt-payload-binding
    aac/                   AAC capsule verification from agent-action-capsule/test-vectors/
  openai-shaped/
    request/               OpenAI chat/completions request digest cases
    response/              Non-streaming response digest cases
    sse/                   SSE reassembly + digest cases (float-free, stable)
  dup-key/                 Duplicate-key MUST-reject cases (stable)
  response-digest/         Two-domain declaration with declared transforms (stable)
```

## Duplicate-key cases

| ID | Input (summary) | Mechanism |
|---|---|---|
| `dup-literal` | `{"key":"v1","key":"v2"}` | Literal byte duplicate |
| `dup-escape-equiv` | `{"key":"v1","key":"v2"}` | Same after escape processing |
| `dup-nfc-nfd` | `{"Å":"v1","Å":"v2"}` | Same after NFC (see Rule 2 departure) |
| `dup-before-normalization` | `{"a":null,"a":"v"}` | Dup detected before absent-field normalization |

## SSE reassembly cases

SSE vectors are separate because the digest domain differs: the sidecar
digests the REASSEMBLED chat.completion object (same shape as a non-streaming
response), not the raw SSE bytes.  Digests are stable because the reassembled
objects contain no floating-point values.

| ID | What it covers |
|---|---|
| `sse-text-basic` | Simple text content delta sequence |
| `sse-tool-call` | Tool-call delta sequence with function arguments |
| `sse-reassembly-stable` | Same generation via stream and non-stream paths produces the same digest |

## Response-digest domains

The sidecar declares two distinct digest domains per exchange:

| Domain | Field | Pre-image |
|---|---|---|
| Raw upstream | `response_digest` | `_stringify_floats(raw_upstream_json)` |
| Forwarded copy | `forwarded_copy.digest` | `_stringify_floats(forwarded_copy_json)` |

`forwarded_copy.transforms` lists which transforms fired.  An empty list means
the two digests are equal; a non-empty list means they differ and the capsule
explains why.

| ID | Transforms | Relation |
|---|---|---|
| `domain-no-transform` | `[]` | `forwarded_copy.digest == response_digest` |
| `domain-content-dropped` | `["content_dropped_with_tool_calls"]` | digests differ |
| `domain-id-minted` | `["tool_call_id_minted"]` | digests differ |

---

## What changes when the number rule lands

When Anton confirms the number representation rule (or the 2026-08-19 session
settles it), the following files change and NOTHING else:

**In `generate_vectors.py`:**
1. The `_stringify_floats_canonical(value)` function currently delegates to
   Python `repr()`.  Replace the `repr(float)` call with the declared rule's
   float-to-string function.  One function, one change.
2. The `_number_rule_pending` guard in `_build_openai_vector()` switches from
   `True` to `False` once that function is updated.

**Generated vector files (run `python generate_vectors.py` after the above):**
3. Every `openai-shaped/request/*.json` with `"_number_rule_pending": true`
   gets its `"digest"` field filled in.
4. Every `openai-shaped/response/*.json` with floating-point values similarly.
5. `vectors/base/manifest.json` `generated_at` timestamp updates.

**NOT changed by the number rule:**
- All `dup-key/` vectors (no floats, digests are already stable).
- All `sse/` vectors (reassembled objects have no floats, digests are stable).
- All `response-digest/` vectors (test cases are designed float-free).
- The NFC departure statement (Rule 2 above).
- The duplicate-detection ordering (Rule 3 above).
- The `base/` repackaged vectors (those are from the sibling repos and don't change here).

---

## Harness contract

* Feed `input_bytes_hex` (decoded to bytes) directly to the implementation.
* Never parse-and-reserialize between receipt and digest computation.
* For MUST-FAIL cases: the implementation must signal rejection; the harness
  must verify the rejection signal, not merely the absence of a digest output.
* For PASS cases: the harness must verify the digest byte-for-byte against the
  vector's `digest` field (or skip if `digest` is null — do not silently pass).
