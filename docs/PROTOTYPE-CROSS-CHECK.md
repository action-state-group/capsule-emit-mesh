# prototype_cross_check — output-vs-claimed-config, scaffolding only

> **Read this first.** Every result this produces is a `prototype_cross_check`:
> **probabilistic, a prototype, NOT "verified", and it NEVER "gets caught".**
> It is a recorded cross-check that **raises or lowers confidence** in the
> claimed config — never a pass/fail verdict, never an accusation. If you want a
> decision, you supply the policy on top and you own it.

## What problem this is scaffolding for

A capsule already **pins the node's config claim**: model identity,
quantization, and a hardware class (GPU / VRAM / SoC). That pinning is the
existing **verify-after-advertise** work (`advertisement.py`,
[`TRUST-MODEL.md` §12.3](TRUST-MODEL.md)). Reconciliation there answers *did the
node serve the model/quant/hardware it advertised* by comparing two
self-attested facts field-by-field.

A different, **harder** question sits next to it: *is the output the node
returned even plausible for the config it claims?* A node could advertise
`Llama-3.2-3B / Q4_K_M` on an on-device SoC, keep that promise on paper, and
still return output that a 3B/Q4 model on that hardware could not have produced
(wrong size, impossible token rate, …). Answering that **well** needs a
statistical reference model of expected output per `(model, quant, hardware)` —
an open-ended data-collection research effort that is **explicitly out of scope
here**.

## What actually ships (deliberately descoped)

Only the scaffolding, so the real model can be attacked into place later:

1. **The sealed config claim, exposed cleanly** — `ConfigClaim`, a thin honest
   view over what the capsule already pins (via `Advertisement` or a
   `serving_provenance` block). It re-pins nothing and invents nothing; a field
   the config didn't claim stays `None` and reads as `inconclusive`, never a
   fabricated value.

2. **A typed seam** the future real model plugs into with **no caller change**:

   ```python
   check_output_against_config(config_claim, request, response) -> CrossCheckResult
   ```

   The implementation is an `OutputCrossChecker` Protocol; the real statistical
   model is a drop-in replacement passed as `checker=`.

3. **A trivial baseline** behind that seam (`baseline_cross_check`,
   `checker_id="trivial-baseline/v1"`): **token-rate / output-shape sanity
   only.** Nothing statistical or learned —
   - **completion-length shape**: an empty completion under a positive cap, or a
     completion over the requested cap, *lowers* confidence; a plausible length
     *raises* it a little;
   - **tokens/sec band**: `completion_tokens / elapsed_ms` against a **wide,
     hand-set** band for the claimed hardware kind. Outside *lowers*; inside
     *raises*. The band is **illustrative rails, not measured references** — do
     not read precision into it.

## The result is not a verdict

`CrossCheckResult` has **no** `passed` / `fail` / `verified` field, and none is
ever added (the same "no silent green" discipline `advertisement.py` keeps). Its
only summary is `confidence_direction`, a closed set:

| direction      | meaning                                                        |
| -------------- | -------------------------------------------------------------- |
| `raises`       | output is plausible for the claimed config (weak signal)       |
| `lowers`       | output is **less** plausible — **a reason to look**, not a catch |
| `neutral`      | checks ran, nothing moved confidence                           |
| `inconclusive` | not enough sealed facts to check at all                        |

Every result carries the permanent `label = "prototype_cross_check"` and the
`PROTOTYPE_CROSS_CHECK_NOTE`, so a downstream reader can never mistake it for a
verification.

## Why ship scaffolding, not the real thing

So a **red-team (B5b) can attack the approach before anyone builds the real
model.** The trivial baseline is intended to be *broken*: find the output that a
cheating node returns which sails through the coarse rails, and we learn whether
output-vs-config cross-checking is worth the data-collection effort at all —
cheaply, before that effort is spent. The honest weaknesses are in the code on
purpose (e.g. unknown hardware widens the band toward uselessness; the band is
hand-set; the baseline reads only facts the record already seals).

## Neutrality

Meter, not price. The baseline reads metered facts the record already seals
(token counts; wall-clock / compute milliseconds via the neutral
`compute_meter` block). It carries **no currency, rate, invoice, or Authority**,
and there is no field that could hold one.
