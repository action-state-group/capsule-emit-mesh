<!-- SPDX-License-Identifier: Apache-2.0 -->
# Paid-inference evidence — `paid-inference/v1` contract + `x-mesh-payments-v1` block, aligned to mesh-llm #1926 @ `166cc72c4`

> **Design only.** Nothing in this document changes code. It supersedes the pre-alignment
> draft written against `45dc8beb3` (kept in the ops workspace's research trail, not this
> repo, as `mesh-paid-inference-evidence-2026-09-21.md`) and updates the contract rows and
> the block doc to the behaviour on `feat/lightning-payments` at `166cc72c4`, which is
> CI-green and ready from the upstream side. Field names below are cited against that tree.
> The fixture re-capture this design implies is tracked separately (§5) — it is not done
> in this document.

## 0. What moved underneath this contract since the last draft

Everything below is a behaviour change on `feat/lightning-payments` between `45dc8beb3`
(the tree the previous draft read) and `166cc72c4` (current head), each cited against the
source:

- **Input invoice expiry: 300 s → 60 s**, tied at compile time to how long the seller
  waits for the input payment (`mesh-llm-payments::lifetimes`; `docs/specs/lightning-payments.md`,
  "Wallet and persistence"). This is also how long an unpaid input invoice can hold a peer
  blocked.
- **New receivables state `lapsed`.** `crates/mesh-llm-payments/src/ledger/receivables.rs`
  guards the transition `state='unpaid' → state='lapsed'` on: the invoice expired,
  `INPUT_LAPSE_GRACE` (60 s, covering wallet-observation lag) has passed, the request
  finished, and `serving_accounting.tokens=0` (zero output delivered). A lapsed peer is
  **admitted again automatically** — the policy choice is that only unpaid *delivered
  output* blocks a peer, never an unpaid-and-abandoned input.
- **`mesh-llm wallet blocked` / `wallet unblock PEER`** (`ledger/receivables.rs`
  `blocked_peers` / `unblock_peer`, `control.rs::ControlCommand::{Blocked,Unblock}`) is the
  provider's durable debt list. `unblock_peer` marks a peer's `unpaid` receivables
  `forgiven` and marks delivered-but-uninvoiced output forgiven
  (`serving_accounting.forgiven=1`) — an operator override, not a refund: "a forgiven
  invoice paid later is still recorded as received" (spec, "Wallet and persistence").
- **A 2-second final wallet lookup at the deadline** while the output buffer is still
  intact, before a request is allowed to lapse.
- **Delivery pauses at 512 buffered tokens** (`PRE_PAYMENT_OUTPUT_TOKENS`) but the default
  scheduler keeps decoding to `max_tokens` behind the gate — documented explicitly as
  bounding buffered bytes, not GPU work.
- **Accepted residual risk, stated in the spec, not fixed by it:** the payer's input
  payment settles, but the provider's wallet is unreachable at the deadline lookup → the
  provider records `lapsed` and re-admits the peer, while the payer has genuinely paid for
  prefill with no output and no refund path. **Lapsed rows are not rescanned** by background
  recovery; a late receipt is recorded only by a subsequent explicit lookup for that
  request.
- **Paid path now resolves public model names to their served name** (`166cc72c4` itself)
  — a model advertised/priced under a catalog or Hugging Face public ID previously 503'd on
  the paid path even though the free path already mapped it.
- **Balance is checked at prefill time, not re-verified at settlement** — the
  `terms_accepted` cap is approved against whatever the wallet balance showed when
  authorization ran, which can go stale before the invoice is actually paid (§2).
- **Client node ids are ephemeral per restart**, so `wallet blocked`/`unblock` is a
  friction against a session, not an identity — unchanged from the previous draft's
  posture on peer-asserted identity, restated here because it now has a durable ledger
  effect (the debt list) attached to it.

## 1. `x-mesh-payments-v1` — the plugin capsule payload block (unchanged shape, one field-value update)

The block still lives **only** in `capsule-emit-mesh`'s plugin `compute_attestation` block,
the same place `x-mesh-coordinator-receipt-v1` already lives
(`mesh_coordinator_receipt_emitter.py`) — never in `agent-action-capsule` core, never
proposed upstream. Typed refs and digests only: no BOLT11 strings, no preimages, no wallet
records beyond the pointer fields named here.

**Field change against the previous draft (Steven/PM ruling, 2026-09-23, on the sibling
`[mesh-paid-inference-fixtures]` item, applied here since it is exactly this block's
shape):** `payment_intent_digest` is **dropped**. The previous draft had the requester hash
its own local-only `PaymentIntent` as a second, distinct digest from the provider's
`RequestTerms` digest — but no such requester-intent digest exists upstream, and the ruling
is explicit: never fabricate one. The join is instead **`terms_digest` computed
independently by each side over its own copy of the same `RequestTerms` fields** (the exact
construction the payer-side evidence hooks already define — JCS SHA-256 over `exchange_id`,
`payee`, `model`, `pricing`, `input_tokens`, `max_output_tokens`, `max_total_msat`,
`expires_at_ms`), plus `payment_hash` once an invoice exists. Two independently-hashed
copies that produce the same digest are the dual commitment; the join rule itself is
otherwise unchanged from the previous draft: two producer claims citing the same
`exchange_id`, never a third object, never silently promoted to bilateral from one side
alone.

```json
{
  "v": 1,
  "kind": "mesh-payments",
  "terms_digest": "sha256:...",
  "input_invoice_ref": { "payment_hash": "...", "amount_msat": 12345, "expiry": "..." },
  "input_settlement_ref": { "payment_hash": "...", "status": "succeeded" },
  "output_invoice_ref": { "payment_hash": "...", "amount_msat": 6789, "expiry": "..." },
  "output_settlement_ref": { "payment_hash": "...", "status": "succeeded" },
  "pricing": { "input_rate": 500, "output_rate": 1500, "granularity": 1000 },
  "authorized_max_msat": 10000,
  "final_paid_msat": 9400,
  "correlation": { "exchange_id": "...", "payment_request_id": "..." }
}
```

**One value-space update against head:** `input_settlement_ref.status` /
`output_settlement_ref.status` are no longer just `"succeeded"` — the source enum they are
read off (`receivables.state`) is `unpaid | paid | lapsed | forgiven`
(`ledger/receivables.rs`). A record built after the segment resolves must carry whichever
of `succeeded | lapsed | forgiven` applies; `unpaid` never appears in a sealed record
because the block is only emitted once a segment resolves. `lapsed` and `forgiven` are
each possible on **either** segment independently (input can lapse per §0; output can be
forgiven per `unblock_peer`), so a reader must not assume "settlement ref present" implies
"paid" — it now means "resolved," and the `status` field carries which way.

**The `terms_accepted` cap, one sentence (do-step 3):** `authorized_max_msat` records what
the requester's policy approved against the wallet balance it read at authorization time —
a check against a snapshot, not a hold on funds — so it is a claim that spend was
authorized under a *then-current* balance, never a claim that funds were reserved or
remained available through settlement.

## 2. `paid-inference/v1` — contract rows, updated to head (11 rows)

Naming and status-vocabulary constraints are unchanged from the previous draft:
`paid-inference/v1` is a **named contract**, not an eighth profile value (the profile set
stays the seven already closed by the internal spec); the two settlement rows carry only a
`ref` per the settlement stub rule; per-requirement status is the existing eight-value
vocabulary, contract result the existing four-value projection. Rows 1–7 are the original
set, restated; rows 8–11 are new, for the head-behaviour states this contract was silent
on.

| # | statement | profile | epistemic type(s) | evidence |
|---|---|---|---|---|
| 1 | A priced offer for the requested model existed and was addressable | outcome | `producer_claim` | the provider's advertised offer (`GET /v1/models` `payment` object) or the peer pricing-gossip record already covered by `mesh-inference-exchange` |
| 2 | The spend was authorized under both parties' own caps before any payment | obligation | `producer_claim` (bilateral) | matching `terms_digest` independently hashed on both sides + `payment_hash`, joined by `correlation.exchange_id` |
| 3 | The input charge settled before generation began | settlement (stub, `ref` only) + outcome (ordering) | `system_of_record_fact` (settlement) + `producer_claim` (ordering) | `input_settlement_ref`; ordering evidence is the same `chain.relation: follows` sequencing `mesh-inference-exchange` already registers |
| 4 | Inference completed | outcome | `producer_claim` | the provider's own completion signal (`effect.type: inference_completion`) |
| 5 | M tokens were delivered | outcome | `producer_claim` | `delivery_watermark=transport_accepted`, M = `Frame::OutputInvoice.tokens` |
| 6 | The output invoice does not exceed the delivered watermark | obligation | `derived_metric` | comparison of row 5's watermark against the invoiced token count |
| 7 | The output charge settled | settlement (stub, `ref` only) | `system_of_record_fact` | `output_settlement_ref` |
| 8 | The input invoice lapsed unpaid and the peer was re-admitted | process | `system_of_record_fact` | the provider's own `receivables` row transition to `state='lapsed'` (`unpaid` past expiry + `INPUT_LAPSE_GRACE`, request finished, zero tokens delivered); provider-only — the payer's sealed lifecycle cannot observe a lapse it did not cause (§3) |
| 9 | Output was delivered without a settled invoice, recorded as receivable debt | obligation | `system_of_record_fact` | the provider's `receivables`/`serving_accounting` row for the peer (`PeerDebt{kind: unpaid_invoice \| uninvoiced_output}`), listed by `wallet blocked` |
| 10 | An operator forgave the peer's recorded debt | human_role | `system_of_record_fact` | `unblock_peer`'s ledger write (`receivables.state='forgiven'`, `serving_accounting.forgiven=1`) — an explicit operator action, its own event, never folded into row 9 |
| 11 | The input charge settled but zero output was delivered (residual risk, never silent) | outcome | `derived_metric` | comparison of `input_settlement_ref.status=succeeded` (row 3) against row 5's watermark = 0; this is the accepted residual case from §0 and must render as its own state, never as a quiet `SATISFIED` on row 3 with nothing said about the missing output |

Per-requirement status and the four-value contract projection are unchanged from the
previous draft — nothing here proposes new status vocabulary.

## 3. "Why unpaid" — derivation from the payer's own sealed lifecycle alone

This is the concrete use of the reconcile/close design
(`[a18-mesh-reconcile-close-v0-design]`, `docs/DESIGN-reconcile-close-v0.md` on its own
branch) — that design defines how two sovereign ledgers get compared; this section only
states what a **single** sealed lifecycle (ours, the payer's `payment.lifecycle.v1`
events) can and cannot conclude on its own, and is deliberately not a restatement of that
design's join mechanics.

From the payer's sealed events (`terms_accepted`, `input_invoice_issued`,
`input_settlement_observed`, `output_invoice_issued`, `output_settlement_observed`,
`final_accounted`):

| payer-side observation | derivation |
|---|---|
| `terms_accepted` present, no `input_settlement_observed`, and a budget/approval decline recorded | **never submitted** — the payer's own policy declined to pay |
| `input_settlement_observed` present with a `wallet_reported` failure recorded after the invoice's expiry | **submitted late** — the payer tried and the wallet's own report shows it missed the window |
| `input_settlement_observed` success, but the exchange otherwise reads as unpaid from outside (row 8/11) | **the residual case** — the payer's wallet reports success while the provider's own deadline lookup did not observe it in time (§0's accepted residual risk); this is not a payer failure |

**The provider's ledger alone cannot distinguish the first two states** — from the
provider's side, "the peer never tried" and "the peer tried and the wallet reported failure
after expiry" both look identical: an invoice that expired unpaid. Mic, 01:33 in the
thread: *"we need to be clear why something was non paid — did they never try."* Only the
payer's own sealed lifecycle carries the distinction (whether `input_settlement_observed`
exists at all); a one-sided read of the provider's `lapsed` row (row 8) is silent on which
of the three branches actually happened, which is exactly the gap the two-sided reconcile
closes.

## 4. Vocabulary check

Boundary checked, clean. `settlement`/`settled`/`lapsed`/`forgiven`/`blocked` are
mesh-llm's own payments vocabulary, cited against its source, not our renaming of it.

## 5. Fixture re-capture — **not done in this document, blocked-on-branch**

Do-step (4) of `[mesh-paid-inference-evidence-align-1926-head]` (re-capture fixtures on
`166cc72c4` with `payment.lifecycle.v1` declared: happy path, long output pause/resume,
never-pays lapse+auto-admit, killed-after-delivery blocked→self-paid-on-restart) is not
attempted here. It depends on `[mesh-provider-lifecycle-events-upstream-pr-prep]`'s fork
branch (claimed `c-provider-lifecycle`, still `in-progress` at time of writing) and on
`[mesh-paid-inference-fixtures]` building against that branch, per the dependency note on
this task. Duplicating either here was explicitly out of scope. Pick this design's rows 8–11
and §3's derivation table up unchanged once that branch is ready — nothing above should need
to change to add the fixtures, only to exercise it.

## 6. Issue-draft refresh — pointer, not duplicated here

The held provider-side-emission issue draft
(`mesh-1926-provider-lifecycle-issue-draft-2026-09-23.md`, Steven posts) is refreshed as
its own edit alongside this document to name the receivables states
(`unpaid → paid | lapsed | forgiven`, `blocked`/`unblock`) as the provider-side emission
points, joined on `exchange_id` — see that file's own history for the diff; this document
does not restate upstream-bound comment text (boundary: capsule/witness vocabulary stays
out of anything posted to `Mesh-LLM/mesh-llm`).
