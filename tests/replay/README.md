# Replay spot-check vector suite — capsule-emit-mesh

Fixtures for `tools/replay_spot_check.py`, the C2a replay spot-check harness
(`docs/TRUST-MODEL.md` §3 Class C). Mirrors the layout convention of
`tests/canonicalization/` and `tests/conformance/`: hand-authored request/
response pairs, one directory per demonstrated case.

## What C2a is, in one paragraph

A capsule already commits the request digest, generation parameters,
execution-bundle identity and runtime. At temperature 0 with a pinned seed,
re-running the request and comparing is exact rather than statistical — no
new cryptography, no access to intermediate activations. The comparison
domain is `response_digest`: `capsule_sidecar.digest_json()`, jcs-n over the
float-stringified raw upstream response — the same function the sidecar
already uses to build a capsule, imported rather than re-implemented so
there is one definition of "match."

## Scope — read before extending this suite

This harness is a comparator, nothing else:

- **No scoring, no trust rating, no trust-adjustment.** `SpotCheckResult` is
  `{domain, digest_a, digest_b, match, advisory}` — a boolean and two
  digests, not a score. That is a standing constraint of the task this
  suite was built for, not a stylistic choice: trust-rating/scoring logic on
  top of this comparison is explicitly Authority-tier and out of bounds for
  this neutral, public-repo lane.
- **A mismatch opens an investigation, not a verdict.** `TRUST-MODEL.md`
  names two independent, expected confounds that produce a mismatch with no
  dishonesty involved: model sampling non-determinism, and execution across
  different hardware (GPU reduction order is not deterministic across
  silicon — C2a's precondition is one hardware class). The `advisory`
  string on every `SpotCheckResult` says this; it is a fixed constant, never
  computed from the outcome, so nothing about severity is implied by a
  mismatch appearing.
- **Text-only fixtures, deliberately.** `docs/SUPPORTED-PORT-RERUN.md`
  documents a *third*, independent confound specific to tool-call turns:
  the normalizer mints tool-call IDs containing wall-clock timestamps
  (`call_mesh_{ms}_{index}`), which are in the digested bytes and make
  `response_digest` run-unique on tool-call turns regardless of sampling.
  These fixtures avoid tool calls so the two demonstrated cases below
  isolate the thing this harness is actually checking (sampling identity)
  from that separate, already-documented confound.

## Cases

| Directory | Demonstrates |
|---|---|
| `vectors/matched/` | Two responses with identical content but different JSON key order and formatting — `response_digest` matches (jcs-n canonicalizes key order), so the harness reports `match: true`. |
| `vectors/mismatched/` | Same request; `response_b` has exactly one sampled token flipped (`"4 GPU-hours"` → `"5 GPU-hours"`) — `response_digest` differs, so the harness reports `match: false`. |
| `vectors/volatile-fields/` | Same content as `matched/`, but `response_b`'s top-level `id`/`created` are backend-minted-fresh (different from `response_a`'s) — the fields in `REPLAY_VOLATILE_FIELDS` are excluded before digesting, so the harness still reports `match: true`. This is the shape a genuine second live firing actually produces: `id`/`created` always differ between two calls even when the model output is byte-identical. |

Both directions are exercised in `tests/test_replay_spot_check.py`, per the
negative-check mandate (QUEUE_PROTOCOL §7): a check that only ever shows the
matched case would never prove the mismatch path actually fires.

`request.json` in each directory is included for context (what a live
`tools/replay_spot_check.py live` run would have pinned and sent) but is not
read by the offline `compare` path — the offline tests exercise
`response_a.json` / `response_b.json` only.
