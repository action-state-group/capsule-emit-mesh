# SSE streaming transcript — answer to #1331

Nick,

You asked in #1331 whether "host-computed request and response byte digests
match independent test calculations" extends to the streaming path.  Here is the
answer.

---

## The definitional question: what does the streaming transcript cover?

**Frame payloads only** — the parsed JSON objects from the `data:` lines, not
the complete encoded SSE frames and not just the raw byte stream.

Here is why.  An SSE intermediary may legally change:

- Line terminators (`\n` vs `\r\n` vs `\r` — all three are valid SSE)
- Whether there is a leading space after `data:` (both `data: X` and `data:X`
  are valid)
- Comment lines (`:` prefix — a proxy may insert heartbeats or strip them)
- `retry:` fields (the retry interval is transport advice, not generation content)
- HTTP chunk boundaries (chunked transfer is transparent to SSE; chunk edges
  have nothing to do with event edges)

None of these changes the LLM's generation.  If the digest covered any of them,
a verifier on a different transport stack could not independently reproduce the
same value — the digest would be a function of the transport, not the model.

Frame payloads are what remains after stripping everything the transport may
legally touch.  They are what the LLM generated.

---

## How the sidecar computes the streaming response_digest

```
parse_sse_stream(raw_sse_bytes):
    split on \n, \r\n, or \r
    for each "data:" line, strip the optional leading space
    skip: comments, retry:, [DONE], empty lines
    JSON-parse each payload → list of frame objects

reassemble_sse(frame_payloads):
    fold role/content/tool_calls deltas in delivery order
    (same logic as capsule_sidecar.reassemble_streamed_response)

response_digest = jcs-n(reassemble_sse(parse_sse_stream(raw_bytes)))
```

The reassembled object has the same shape as a non-streaming `chat.completion`
response.  The digest is computed over THAT object, not over the SSE frames.
Usage fields are excluded (they do not appear in the main chunk stream in
mesh-llm and would create a number-rule dependency).

---

## We are the independent calculation

The verification box says "host-computed ... match independent test calculations."

**The sidecar IS the independent test calculation.**

The sidecar computes `response_digest` from the frame payloads it observed on
the wire directly — not from what the host application layer reported.  The
signed capsule is the cryptographic evidence.  A third-party verifier can:

1. Hold the transcript (the list of frame payloads).
2. Run `reassemble_sse` → `jcs-n`.
3. Compare to the `response_digest` in the capsule.

If they match, the verifier has confirmed what the LLM actually generated,
independent of the host.  The host cannot substitute different response bytes and
claim the digest matches.

This is what makes the streaming path non-trivial: without independent
computation, a "streaming digest" is just another field the host fills in.
With it, the capsule commits the sidecar's direct observation, verifiable by
replay.

---

## What is still pending (number rule)

Token counts and timing fields may carry floats in future mesh-llm versions.
Until the float-to-string rule is settled (Anton's reply / 2026-08-19 session),
any transcript whose reassembled object contains floats carries
`response_digest: null` and `_number_rule_pending: true`.  Frame payloads
themselves — role, content, tool_calls — are string-valued and do not trigger
the pending guard.

The `sse_digest_domain: "frame-payloads"` declaration is independent of the
number rule and is settled now.

---

Draft only — Steven will share this when the timing is right.
