<!-- SPDX-License-Identifier: Apache-2.0 -->
# Red-team of rung-1 accountability (B5a)

**What "rung 1" is here.** A signed, zero-retention, hash-chained capsule ledger
(Layer 0), a local append-only MMR over it (Layer 1), periodic signed COSE-wire
checkpoints (Layer 2), and an independent witness that counter-signs those
checkpoints (Layer 3, `register_checkpoint`). This document attacks **only** what
rung 1 alone buys. It deliberately does **not** lean on the config-fingerprint
(B2) or binary attestation (B3) — those are separate rungs with their own
red-teams.

**Method.** Each attack below is backed by a concrete, runnable harness in
[`tests/test_redteam_rung1.py`](../tests/test_redteam_rung1.py), executed against a
real throwaway ledger + the live checkpoint/witness machinery (with an *honest*
in-process fake witness — no network). Each attack's outcome is recorded as:

- **caught** — the machinery rejects it; a verify goes RED.
- **labeled** — it is not rejected, but it is named honestly in the record (a
  verifier can see the degradation).
- **residual (uncaught)** — it succeeds and rung 1 alone has no handle to see
  it. Residuals are the product of this exercise, not an embarrassment — each
  one names the rung that closes it.

Run the evidence:

```
python3 -m pytest tests/test_redteam_rung1.py -v
```

## Weak-links table

| # | Attack | Mechanism | Outcome | Evidence (test) | What closes it |
|---|--------|-----------|---------|-----------------|----------------|
| 1 | **Ledger equivocation** | Present two divergent histories at the same position: rewrite / roll back an already-checkpointed leaf (same length, different content) and offer the forked ledger. | **caught** | `test_attack1_equivocation_rewrite_breaks_root`, `test_attack1_equivocation_consistency_proof_goes_red` | Already closed by rung 1. The MMR root is a content commitment: a rewritten leaf recomputes to a **different** root than the witnessed checkpoint signed, and `verify_checkpoint_consistency` over the forked log goes RED. The signed+witnessed checkpoint pins one history; a second is unforgeable without the node key. |
| 2 | **Nonce replay** | Replay a captured genuine `client_nonce` verbatim on a later, unrelated exchange, so a stale/precomputed record looks freshly bound to *this* exchange. | **labeled** (within a node lifetime) / **residual** (across restart or across nodes) | `test_attack2_nonce_replay_within_lifetime_is_labeled`, `test_attack2_nonce_replay_across_restart_is_residual` | In-lifetime: `_resolve_client_nonce` dedups against `seen_client_nonces` and labels a repeat `client_supplied_replayed` — named, never silently upgraded. **Residual:** `seen_client_nonces` is in-memory and per-node, so replay across a process restart or across two independently-operated nodes reads as fresh again. Closed by a **shared/persistent seen-nonce store** (out of scope for a PoC sidecar; must be stated explicitly, not assumed away). |
| 3 | **Dropped / withheld checkpoint** | Keep appending but never anchor the tail — or hide the newest checkpoint and present only an older one. | **labeled** | `test_attack3_dropped_checkpoint_surfaces_as_lag`, `test_attack3_withheld_newest_checkpoint_leaves_stale_watermark` | The witness state names the un-anchored tail as an explicit **lag** ("witnessed up to entry N … M more entries appended since"); the witnessed watermark never silently advances to the live height. A verifier sees the gap. **Honest boundary:** lag *reveals* an unwitnessed tail; it does not by itself *force* the node to ever anchor. A node that just stops checkpointing shows as perpetually lagging — turning that signal into an obligation is a **requester/monitor** concern (B6a), not rung 1's. |
| 4 | **Selective-log (the big one)** | An **honest, fully witnessed** log that simply **never seals FAILURES**. Every sealed entry is genuine, chained, checkpointed and witnessed — a perfect, witness-consistent chain — but the *set* of exchanges it chose to seal is a fraudulent subset (all successes, no failures). | **residual (uncaught)** — *by design* | `test_attack4_selective_log_is_perfectly_witness_consistent`, `test_attack4_witness_cannot_assert_coverage` | **Nothing in rung 1 closes this, and that is the point.** The harness builds two ledgers from the same exchange stream — one complete, one successes-only — and shows the selective log passes *every* integrity check: witnessed, root-consistent, clean witness state. The witness proves **INTEGRITY** (what was logged wasn't tampered) but never **COVERAGE** (that everything that happened was logged). The `WitnessRecord` carries no field constraining which/how-many exchanges occurred. Closed by **B6a — requester-side correlation / requester-held receipts**, which supplies the independent count of true exchanges that rung 1 structurally lacks. |

## The shape of the residuals

Rung 1 is an **integrity** instrument, not a **coverage** instrument. Everything
it signs, it signs faithfully; a verifier can trust that a witnessed checkpoint
pins exactly one un-rewritten history (attack 1) and that any un-anchored tail is
named as lag (attack 3). What rung 1 cannot do, alone, is prove that the history
it faithfully pins is *the whole* history:

- **Attack 4 (coverage)** is the load-bearing residual. An honest-looking witness
  cannot assert coverage; only a party who independently knows an exchange
  happened (the requester) can notice its absence. That is **B6a**.
- **Attack 2's residual** (replay across restart/node) is a narrower coverage-ish
  gap in the *anti-replay* property and is closed by persistence/sharing of the
  seen-nonce set, not by anything in the checkpoint machinery.

Neither residual weakens the caught/labeled results above — they bound exactly
where the rung-1 guarantee stops, which is the useful output of a red-team.
