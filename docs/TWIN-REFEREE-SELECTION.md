# Twin & referee selection — independence-first, and why it isn't nearest

> **Read this first.** `twin_selection.py`'s `select_twin`/`select_referee` are a
> **requester-side, per-request "who do I ask" policy**. They compute nothing
> that is published, gossiped, or attached to a peer as a standing figure — the
> independence breakdown below is recorded once, alongside the ONE twin/referee
> comparison it informed, so a verifier can see why that pairing was chosen. It
> is never a public ranking, and it is never proof that the chosen peer actually
> is independent — see "What this does not prove" below.

## The problem

Corroboration (`twin_adjudicator.py`) and adjudication (E17c, upstream-gated)
only mean something if the second/third node asked is actually a different
party. Two machines sitting in the same rack, run by the same person,
"corroborating" each other proves nothing about the answer — it proves that
one person's two boxes agree with themselves. Before this module existed, the
twin/referee were hand-picked via `x-mesh-target`; nothing biased that pick
toward independence, and nothing recorded why a pick was made.

Two problems have to be solved, in order:

1. **Comparability.** Asking a different model isn't corroboration — it's
   "different model, different answer." Same-model is a hard gate.
2. **Independence.** Among same-model peers, prefer the one least likely to be
   the same operator / same box / same rack as whoever it's being compared
   against.

## What's observable per peer

From `/api/status` `peers[]`, today:

| Signal | What it's a proxy for |
|---|---|
| `weights_digest` | The real same-model key (identical across nodes running the same weights file — **not** the per-node `local-gguf/sha256-...` load id, which differs node to node for the same weights). |
| `rtt_ms` / `latency_source` (`direct` vs `relay`) | Network distance from the requester's own vantage point. |
| `owner` (id + verified) | Operator identity — weak today (opt-in, self-asserted; see `node_ownership.py`'s `IDENTITY_LIMITATION_CAVEAT`). |
| `hostname` / `gpus` / `is_soc` | Co-location / same-fleet hints. |
| `first_joined_mesh_ts` | Tenure — a brand-new peer is cheaper to stand up on demand than a long-lived one. |

## The algorithm

**Step 1 — comparability (hard gate).** Candidates are peers with
`state == "serving"` whose `weights_digest` matches the target. No match →
`REASON_NO_COMPARABLE_TWIN`; a different model is never substituted.

**Step 2 — independence.** Four components, each `0.0`–`1.0`, combined by
`SelectionPolicy`'s weights (equal by default — "start equal" is the point,
not an accident):

- **network distance** — `latency_source == "relay"` scores `1.0`; otherwise
  `rtt_ms` scaled against `rtt_saturation_ms` (co-located machines are
  low-RTT/direct).
- **operator diversity** — a different `owner_id` scores `1.0` if the
  candidate's owner claim is verified, `0.7` if not (a distinct claim is
  still a heuristic without the signed join-card binding); the SAME owner
  scores `0.0`, a heavy, deliberate penalty. Either owner unknown → `0.5`,
  never assumed independent.
- **fleet diversity** — a shared `hostname` scores `0.0` (near-certain
  co-location); otherwise a shared `(gpus, is_soc)` hardware class scores
  partial credit (`0.3`–`0.6`); distinct or unknown → `1.0`/`0.5`.
- **tenure** — pool-relative: the oldest `first_joined_mesh_ts` among the
  candidates actually being compared gets a small bonus toward `1.0`; unknown
  or indistinguishable tenure is `0.5`. (Deliberately relative, not
  wall-clock — no "now" is ever read inside the selection itself.)

**Step 3 — pick.** The highest-independence candidates within
`tie_band_width` of the top form a band; the pick is a **random draw from
that band** — never the single nearest (likely co-located) and never uniform
over the whole pool (which can draw a co-located candidate anyway).
Randomness confined to the top band stops a target from gaming which
twin/referee it will face, without diluting the independence bias.

**Step 4 — optional history sanity-check.** A caller may pass
`history_check: PeerInfo -> HistorySanityResult` (e.g. wrapping
`ask_history.py`'s bundle-request path). A candidate whose check fails is
dropped and the next band is drawn from what remains. This module never
performs that network round trip itself — see "What this is not" below.

`select_referee(twin_a, twin_b, peers, policy)` runs the same algorithm with
`others = [twin_a, twin_b]`, so a referee is scored for independence from
BOTH twins at once, and additionally requires `twin_a`/`twin_b` to already
share one `weights_digest`. Unlike `select_twin`, owner independence here is
a **hard gate**: a candidate whose `owner_id` is known to equal either
twin's is excluded from the candidate pool outright, not merely scored
`0.0` on the owner-diversity component ([mesh-referee-live-e17c],
2026-09-08 — a mesh where all comparable peers share one operator must
never silently corroborate itself via a same-owner "referee"). If that
hard exclusion leaves zero candidates, `select_referee` falls back to the
full comparable pool — "distinct node key" instead of distinct owner — and
sets `SelectionResult.owner_diversity_limited = True` so a verifier can see
the independence guarantee was narrowed, never infer it silently from a low
score.

## What this does not prove

- **Selection improves the odds of independence — it does not prove it.**
  Two distant IPs can still be one operator. The signal that would actually
  demonstrate a distinct party is a *verified* owner binding — the signed
  join-card `node_ownership.py` already builds, opt-in and not universal
  today. Until then, every owner-diversity component is a heuristic over a
  self-asserted claim.
- **`rtt_ms`/`latency_source` is a network-distance heuristic, not geography.**
  A relay hop and a genuinely distant peer look the same; so does a
  same-datacenter peer behind an unusual route.
- **Nothing here is a public ranking.** The independence breakdown
  (`IndependenceBreakdown` / `selection_rationale_block`) is computed
  per-request and is meant to be recorded alongside the ONE resulting twin
  comparison — never published standing next to a peer's identity, never
  compared across peers outside the request that produced it.

## What this is not

- **Not a network call.** Like `twin_adjudicator.adjudicate()`, `select_twin`/
  `select_referee` are pure functions over a `peers` sequence the caller
  already holds. The one place a round trip could enter — Step 4 — is an
  injected callable this module never dials itself.
- **Wired to a live coordinator path.** `live_referee.py` calls
  `select_referee` to pick the third node, then makes the actual live
  `x-mesh-target` request (see that module) -- the recompute this module's
  pick feeds is real, not held.

## Config

`SelectionPolicy` (defaults in parentheses):

| Field | Default | Meaning |
|---|---|---|
| `weight_network_distance` | `0.25` | Weight on the network-distance component. |
| `weight_owner_diversity` | `0.25` | Weight on the operator-diversity component. |
| `weight_fleet_diversity` | `0.25` | Weight on the hostname/hardware-class component. |
| `weight_tenure` | `0.25` | Weight on the pool-relative tenure component. |
| `tie_band_width` | `0.10` | How close to the top independence value still counts as "tied" for the random pick. |
| `rtt_saturation_ms` | `250.0` | `rtt_ms` at/above this saturates the network-distance component to `1.0` when the peer isn't already `relay`. |

All four weights start equal by design; a deployment with more owner-cert
adoption (more `owner_verified` candidates) may reasonably raise
`weight_owner_diversity` without touching any selection logic.

**Cadence** (how often a twin fires at all — every request, every 10th,
every 5th when sampling is thin) is a **caller-level** decision, orthogonal to
which peer gets picked once a request is made, and is not a `SelectionPolicy`
field. It belongs wherever the request loop lives; a recommended default is
"every 10th request," tightening to "every 5th" when the corroboration
sample is thin.

## Recording the rationale

`selection_rationale_block(result)` returns a JSON-safe dict (schema
`capsule-emit-mesh/twin-selection/v1`) — every candidate's breakdown, the
policy weights used, and the honesty caveat text — meant to be attached to
the REQUESTER's own record (e.g. its `compute_attestation`), never used to
mutate or re-seal the twin's already-sealed capsule (same discipline as the
provider-ack leg of `[mesh-b2-cite-and-ack-wire]`).
