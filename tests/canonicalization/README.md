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
    sse/transcript/        SSE transcript vectors (frame-payload domain, mock-rig verified)
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

## SSE digest domain: why frame payloads

**The digest domain for SSE is FRAME PAYLOADS ONLY** — the parsed JSON objects
from `data:` lines, not the complete encoded SSE frames.

The deciding consideration: a verifier must be able to REPRODUCE the digest from
bytes it did not produce.  Anything an intermediary may legally reformat cannot
be inside the digest without making the digest a function of the transport, not
the LLM's generation.

**Complete enumeration of what SSE permits an intermediary to change:**

| Element | SSE spec status | Consequence for digest |
|---|---|---|
| Line terminators (`\n` vs `\r\n` vs `\r`) | All three are valid per W3C SSE; intermediaries may normalize | CANNOT be in digest |
| Optional leading space after `data:` | `data: payload` and `data:payload` are both valid | CANNOT be in digest |
| Comment lines (`:` prefix) | A sender may insert heartbeat comments at any time; a proxy may add or strip them | CANNOT be in digest |
| `retry:` fields | A proxy may change the retry interval; a sender may add retry between events | CANNOT be in digest |
| Blank lines between events (event boundaries) | The SSE spec defines an event as terminated by a blank line; a proxy may add blank lines within fields or change spacing | CANNOT be in digest |
| HTTP transfer-encoding (chunked framing) | HTTP chunking is transparent to the SSE consumer; chunk boundaries bear no relation to event boundaries | CANNOT be in digest |
| HTTP header values (Content-Type charset, Transfer-Encoding) | Transport metadata | CANNOT be in digest |
| **JSON-parsed `data:` field content** | The LLM's actual generation — this is what the sidecar committed to | **IS the digest domain** |

What survives: the JSON-parsed content of each `data:` field, in delivery order.
This is what the LLM generated.  The transport cannot forge, reorder, or modify
these without breaking the `response_digest` commitment in the capsule.

**Departure from a "complete frames" domain:**  If the digest covered the
complete encoded SSE frame bytes, then two transports producing identical
generations but different line terminators would produce different digests — a
verifier on a different transport stack could not independently verify the same
capsule.  Frame payloads give transport-independence.

## SSE transcript definition

An SSE transcript is the verifiable record of what the sidecar observed from the
LLM's streaming response.  It is the sidecar's side of the `response_digest`
claim: the sidecar computed `response_digest` INDEPENDENTLY from the frame
payloads it saw on the wire.

**Algorithm (mesh-sse-reassembly-v1):**

```
parse_sse_stream(raw_sse_bytes):
  1. Split raw bytes on \n, \r\n, or \r (all valid SSE terminators).
  2. For each line starting with "data:", strip the optional single leading space.
  3. Skip: comment lines (:), retry: fields, [DONE] sentinel, empty lines.
  4. JSON-parse each remaining payload → list of frame payloads.

reassemble_sse(frame_payloads):
  1. Fold role, content, and tool_calls deltas in delivery order.
  2. Exclude usage fields (see USAGE EXCLUSION note below).
  3. Return one chat.completion object (same shape as non-streaming response).

response_digest = jcs-n(reassemble_sse(parse_sse_stream(raw_sse_bytes)))
```

**USAGE EXCLUSION:** Usage fields (`prompt_tokens`, `completion_tokens`,
`total_tokens`) are excluded from the reassembled object and thus from the
transcript digest.  Reasons:
1. Real mesh-llm does not emit usage in the main chunk stream.
2. Usage counts are plain integers, but a future version may emit float-typed
   usage — which would create a `_number_rule_pending` dependency in every
   transcript.  The exclusion is declared explicitly so an implementer knows it
   is a deliberate choice, not an oversight.

**UNFREEZING PRECONDITION for transcript `response_digest`:**  Transcript
vectors carry `response_digest = null` and `_number_rule_pending = true` if the
reassembled object contains floats.  The precondition for unfreezing is identical
to the non-transcript pending vectors: the float-to-string conversion rule must
be settled AND `_stringify_floats_canonical()` updated.  See §"What changes when
the number rule lands" — the same `generate_vectors.py` re-run also regenerates
all transcript vectors.

## SSE transcript and independent verification (#1331)

The `#1331 verification box` states: "host-computed request and response byte
digests match independent test calculations."

**The sidecar IS the independent calculation.**  Here is the claim stated plainly:

> The sidecar computes `response_digest` from the SSE frame payloads it observed
> directly on the wire — NOT from what the host's application layer reported.
> The signed capsule is cryptographic evidence of this independently-computed
> value.  A third-party verifier can replay the transcript (parse the same frame
> payloads, reassemble, jcs-n) and arrive at the same digest.  The host cannot
> substitute different response bytes and claim the digest matches, because the
> sidecar computed it from what actually flowed.

This is the contribution that makes SSE transcript coverage non-trivial: without
the independent computation framing, a "streaming digest" is just another field
the host populates.  With it, the capsule commits the sidecar's view of the
generation, verifiable by anyone who holds the transcript.

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

## SSE transcript cases

| ID | What it covers |
|---|---|
| `transcript-text-basic` | Transcript of text content SSE bytes; verifies frame-payload domain |
| `transcript-tool-call` | Transcript of tool-call SSE bytes; verifies argument concatenation |
| `transcript-mock-rig` | Transcript from a real HTTP exchange with mock_mesh_node.py; verifies independent-verification invariant |

The `transcript-mock-rig` vector is regenerated on each `generate_vectors.py`
run (IDs and timestamps vary).  Its `independent_verification.verified` field
must be `true` after generation; this is the "implemented against the mock rig"
check.

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
5. Every `openai-shaped/sse/transcript/*.json` with floats in the reassembled
   object gets its `"response_digest"` filled in.
6. `vectors/base/manifest.json` `generated_at` timestamp updates.

**NOT changed by the number rule:**
- All `dup-key/` vectors (no floats, digests are already stable).
- All `sse/` vectors at the top level (reassembled objects have no floats,
  digests are stable).
- All `response-digest/` vectors (test cases are designed float-free).
- The NFC departure statement (Rule 2 above).
- The duplicate-detection ordering (Rule 3 above).
- The `base/` repackaged vectors (those are from the sibling repos and don't change here).
- The SSE digest domain declaration ("frame-payloads") — that is independent of
  the number rule.
- The independent-verification framing in transcript vectors — that is
  structural, not digest-value-dependent.

---

## Harness contract

* Feed `input_bytes_hex` (decoded to bytes) directly to the implementation.
* Never parse-and-reserialize between receipt and digest computation.
* For MUST-FAIL cases: the implementation must signal rejection; the harness
  must verify the rejection signal, not merely the absence of a digest output.
* For PASS cases: the harness must verify the digest byte-for-byte against the
  vector's `digest` field (or skip if `digest` is null — do not silently pass).
