<!-- SPDX-License-Identifier: Apache-2.0 -->
# History as a routing input — filter, never rank

> **Design only.** Nothing in this document changes code, and nothing here is posted
> upstream. It is the routing slice of `_work/mesh-sharing-policy-history-and-money-2026-09-24.md`
> §4–§5 (PM note, internal, public-safe wording), narrowed to what the router itself does
> with history once it exists. The policy object that produces the history a router
> consumes — `share.history_segments`, the responder's answer/refuse decision, the record
> push at completion — belongs to the sibling design `[mesh-sharing-policy-v0]`; this
> document assumes that policy exists and asks only "given a history segment, what can a
> router honestly do with it." Cited against `Mesh-LLM/mesh-llm` @ `7d6b9256a` and this
> repo @ `2e3b0b93f`.

## 0. Where this sits

Three designs share one boundary rule (no computed standing, ever) and split cleanly by
who produces vs. who consumes history:

- `[mesh-sharing-policy-v0]` — the policy object, the responder's relationship-keyed
  answer/refuse decision, the record push at completion. **Produces** the history a peer
  can be asked to show.
- `[mesh-adjudications-on-history-card-design]` — how a verdict about a node reaches that
  node's own history card (`adjudications: deliver_to_subjects`, ack/rebuttal). **Shapes**
  what the history card contains.
- **This document** — what a *router* is allowed to do with history once it can ask for
  it: gate a candidate in or out, never weight or order by it. **Consumes** history, and
  only as a filter.

Two more designs this one leans on without restating:

- `[a18-mesh-reconcile-close-v0-design]` (`docs/DESIGN-reconcile-close-v0.md`, on branch
  `a18-mesh-reconcile-close-v0-design`, not yet on `main`) defines the six-state
  MATCHED/A_ONLY/B_ONLY/CONFLICTING/INSUFFICIENT/UNRESOLVED join and the Close record whose
  `close_state` (AGREED/UNILATERAL/CONTESTED) is what `reconciled>=N` in §3 actually counts.
- `docs/DESIGN-paid-inference-evidence.md` (merged) defines the `x-mesh-payments-v1` block
  and the `receivables` state machine (`unpaid → paid | lapsed | forgiven`, `blocked`) that
  §5's money properties read.

## 1. Today's router inputs, and the filter/rank split that already exists

**Single-request routing** ranks by throughput and cache affinity
(`crates/mesh-llm-host-runtime/src/network/openai/routing_rank.rs`:
`rank_candidates_by_context_and_throughput`, `target_throughput_rank_key`), sticky-hashes on
`prompt_cache_key`/`user`, and filters by capability (context headroom,
`capabilities_for_model`) — every signal a peer reports about itself, right now. **Split
placement** (`crates/mesh-llm-host-runtime/src/inference/skippy/topology.rs`,
`plan_package_aware_contiguous_with_signals`) scores `cached_slice_bytes`,
`missing_artifact_bytes`, `availability_score`, RTT and VRAM the same way — self-reported,
present-tense claims.

**The router already has one filter-not-rank precedent, and it is the pattern this design
extends rather than invents.** `x-mesh-target` / `x-mesh-exclude`
(`crates/mesh-llm-host-runtime/src/network/openai/ingress.rs`, `resolve_remote_mesh_route`,
`mesh_headers_force_remote`) let a requester name or exclude specific peers *before* any
ranking runs: `hosts_for_model()`'s candidate list is filtered by the exclude set and (when
a target is given) collapsed to that one peer; ranking only ever runs on what survives.
Naming a target that isn't in the (filtered) candidate set is `RemoteMeshRoute::
TargetUnavailable` — the caller **fails closed with a 409, never substitutes a different
peer** (`ingress.rs` line ~1091, ~996). That fail-closed contract is exactly what §3 below
reuses for `x-mesh-require`.

Nothing in this pipeline today asks whether a candidate has ever *done* anything, whether
anyone else confirmed it, or whether its log was ever caught disagreeing with a
counterparty's. History is the one input class absent from both the single-request and
split-placement paths.

## 2. The pre-routing ask

**Default on, from `share.history_segments: prospective`** ([mesh-sharing-policy-v0] §3):
when routing is about to consider a peer with no history segment on file, it issues one
coarsened `chain_segment` request (`capsule_emit.chain_segment.ChainSegment`, via
`evidence_responder.py`'s existing `chain_segment` subject handling) to that peer. The
answer — or a signed refusal — is recorded as the segment now held for that peer.

**This step changes no routing decision by itself.** It is "look before you leap," not
"refuse strangers": a peer that has never been asked is not penalized, and a peer that
answers is not preferred over one already on file. It exists so that *by the time* a
requirement in §3 is evaluated, the router has looked rather than assumed. A peer that
refuses (`request_malformed` today; a relationship-scoped `not_authorized` reason is
[mesh-sharing-policy-v0]'s addition, not yet one of the `capsule-emit` dependency's
`evidence_request.REFUSAL_REASONS` values — today `request_malformed`,
`coverage_unsatisfiable`, `no_such_record`; this repo consumes that enum from
`capsule-emit`, it does not define it) simply has a recorded refusal instead of a segment —
which is exactly the fact a `history:answered` requirement in §3 reads.

## 3. `x-mesh-require` — the requirement vocabulary, client-held

**Extends #1670's header pair, doesn't replace it.** `x-mesh-target`/`x-mesh-exclude`
(#1670) name or exclude specific peers by identity. `x-mesh-require` is the same
requester-stated-intent header family, but names *properties a survivor must hold* instead
of an identity:

```
x-mesh-require: history:answered
x-mesh-require: reconciled>=3
x-mesh-require: witnessed
x-mesh-require: no-contradictions-30d
x-mesh-require: settled-both-books>=5
x-mesh-require: no-unforgiven-debt
x-mesh-require: no-lapsed-30d
```

(Comma-joined on one header line or repeated, same convention `x-mesh-exclude` already
uses for its comma-separated list — parsing detail for whoever implements this, not fixed
here.)

**Semantics, stated once so every property below is the same shape:**

1. The router resolves the ordinary candidate set exactly as today (capability, then
   `x-mesh-target`/`x-mesh-exclude` if present).
2. For each requirement token, the router filters that set down to candidates whose *held*
   history evidences the property. "Held" means: already on file, or fetched via §2's
   pre-routing ask if a candidate is otherwise eligible and has none yet. A requirement is
   never evaluated against a peer's own unverified claim about itself — only against a
   segment or card this node holds and could show a challenger.
3. Ranking (throughput, cache affinity, price once #1926 lands) runs on survivors **exactly
   as it runs today** — history changes who is in the pool, never their order within it.
4. **No survivor → fail closed with the reason**, the same contract `x-mesh-target`
   already uses (`RemoteMeshRoute::TargetUnavailable` → 409): never silently widen to "any
   peer," never silently drop the requirement. The reason names which property zero
   candidates met, so the caller can decide to relax it rather than guess why the request
   failed.

**Property definitions and their evidence source:**

| property | true when | evidence (what the router actually reads) |
|---|---|---|
| `history:answered` | the candidate answered §2's (or an earlier) segment request | a recorded `ChainSegment` reply, not a refusal, on file for this peer |
| `reconciled>=N` | at least `N` Close records exist against this peer with `close_state: AGREED` | `[a18-mesh-reconcile-close-v0-design]`'s Close capsules — a count, never a rate |
| `witnessed` | the peer's held checkpoint coverage is witnessed, not self-checkpointed | `account_capsule.py`'s existing `coverage_witnessed` field — this property names an already-real thing, it invents nothing |
| `no-contradictions-30d` | zero `CONFLICTING`-state Close records (or zero adjudications with a `contradicted:<owner_id>` attribution) against this peer in the trailing 30 days | Close record states (reconcile design §2) and/or the history card's `adjudications_about_x` counts ([mesh-adjudications-on-history-card-design]) |
| `settled-both-books>=N` | at least `N` exchanges where both wallets' `input_settlement_ref`/`output_settlement_ref` report `succeeded` for the same `payment_hash` | `x-mesh-payments-v1` records (`DESIGN-paid-inference-evidence.md` §1) joined by `payment_hash`, counted, never summed to an amount |
| `no-unforgiven-debt` | the candidate has no `receivables` row in `unpaid` (past grace) or `debt_recorded` without a later `debt_forgiven` for the requester | the provider's own debt list (`wallet blocked` / `receivables.state`), or the requester's own record of having been told so |
| `no-lapsed-30d` | zero `input_invoice_lapsed` events involving this peer in the trailing 30 days | segment counts by kind (§4 of the sharing-policy note: `lapsed` is a counted checkpoint kind) |

Every property above is **a count or a boolean read off records already committed by
someone**, never a rate, average, or score computed by the router. That is the load-bearing
distinction from a ranking weight (§6).

## 4. Splits — the coordinator's policy, the planner untouched

**The coordinator's operator holds the requirement policy**, the same place
`share.history_segments`/`x-mesh-require` for single-request routing lives conceptually —
not per-request, not per-caller, an operator-set default the coordinator applies before it
ever calls into placement.

**The same filter, applied one step earlier.** Before
`plan_package_aware_contiguous_with_signals` (`skippy/topology.rs`) ever sees a candidate
list, the coordinator applies the operator's `x-mesh-require` filter to the stage-candidate
set — identical filter-then-rank shape as §3, just run on the coordinator's candidate pool
instead of the single-request router's. **The planner itself is untouched**: it still
scores `cached_slice_bytes`/`missing_artifact_bytes`/`availability_score`/RTT/VRAM exactly
as today, on whatever survives the filter. History never becomes a placement-scoring input;
it only decides who is eligible to be scored.

**`stages-completed>=N` is explicitly deferred.** It would require a per-stage
participation record — "this node ran slice K of split job J" — which does not exist yet
anywhere in this repo or the reconcile design. Until it does, the only honest split
requirements are the log-level ones already defined in §3
(`history:answered`, `witnessed`, and the others once the underlying record types they read
exist): a requirement can only be stated once there is a record it could actually be false
against. Inventing a plausible-sounding split-specific property ahead of its evidence would
be exactly the "well-formed, unfalsifiable" failure this whole design exists to avoid.

## 5. What money changes here — structure no, questions yes

Restated from the sharing-policy note §5, narrowed to the routing consequence:

1. **Amounts are facts on entries, never sums on cards, and never a routing signal.** No
   candidate is ever preferred because it has paid or been paid more; `settled-both-books>=N`
   is a count threshold a requester sets, not a router-computed total.
2. **Requirements, not ranks — same shape as §3, not a new mechanism.**
   `settled-both-books>=N`, `no-unforgiven-debt`, `no-lapsed-30d` are `x-mesh-require`
   tokens like any other; they filter the same way `history:answered` does. The per-operator
   payments blocklist (`wallet blocked`) stays a **local** deterrent — it changes who *that
   node* will serve, never a value the router propagates or ranks by.
3. **The wallet keeps the money; the log keeps what both sides said about it.** A router
   never reads a wallet balance or a payment amount to decide anything — only the *lifecycle
   records* (`settled`, `lapsed`, `debt_recorded`, `debt_forgiven`) that both sides already
   sealed. Disputes about money are resolved by comparing records (reconcile, §3's
   `no-contradictions-30d`), never by trusting either wallet's number.

**What money forces, in order, before any of §3's payment properties can be evidenced
at all:** provider-side lifecycle events (#2017 — without them, settlement history is
one-booked and every money property in §3 is `INSUFFICIENT` by the reconcile design's own
vocabulary, by construction, not by a routing decision) → the record exchange at completion
([mesh-sharing-policy-v0] §2) → the stage participation record (§4's blocker for
`stages-completed>=N`). This document's money properties are real definitions now; they are
not yet *evidenceable* until that chain closes.

## 6. Why filter-not-rank is the whole point

The mesh community refused reputation. A "history weight" folded into `routing_rank.rs`'s
throughput/cache-affinity score, or into `skippy-topology`'s `availability_score`, would be
reputation entering through the back door of a number nobody labeled as one. A
**requirement the requester states** (`x-mesh-require`) is a policy the *requester* holds,
made checkable against records the requester can inspect — the router does not decide who
is "better," it decides who is *eligible*, exactly the same latitude `x-mesh-target`/
`x-mesh-exclude` already give a requester today. Every property in §3 and §5 is a count or
a boolean on records that already exist independent of this design; none of them are a
computed standing that would survive being asked "computed how, and by whom."

## 7. Vocabulary check

Checked against this document: no `reputation`, `score` (`availability_score` is cited only
as an *existing, unmodified* field name, never repurposed here — no property in §3/§5 reads
or writes it), `rank`ing of peers by history (only ranking of *survivors* by today's
existing signals, unchanged), `trust` as a computed value, KYB/KYC, Authority, Relay,
pricing-of-ours. "Filter" and "requirement" are used throughout in place of any of the
above. `witnessed` and `reconciled` name existing or already-designed record types, not new
scoring concepts.

## 8. Upstream issue — held, not drafted for posting yet

The task's do-step (5) asks for upstream issue text in host vocabulary, held until **both**
`#1926` merges and `#2017` has an answer (checked live against `Mesh-LLM/mesh-llm` at claim
time: `#1926` — OPEN, mergeable, `7d6b9256a`-era head, 14 commits, last updated
2026-09-25T00:20Z; `#2017` — OPEN, 0 comments, posted 2026-09-23). Neither condition is met.
Per the task's own sequencing rule ("two host asks at once is how one gets deferred"), the
draft is written but **held outside this repo** — `_work/mesh-history-as-routing-input-issue-draft-2026-09-24.md`
in the ops workspace, not this repo's `docs/`, matching where the sibling `#1926`
provider-lifecycle draft already lives. It is not posted, and no PR or comment exists
against `Mesh-LLM/mesh-llm` from this task.
