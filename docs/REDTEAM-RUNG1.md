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
  seen-nonce set, not by anything in the checkpoint machinery. This is the **same
  residual `chunk-6`'s `FileNoncePeriodLedger` already solved** in the compiler
  context — whoever closes it should reuse that pattern, not reinvent a store.

Neither residual weakens the caught/labeled results above — they bound exactly
where the rung-1 guarantee stops, which is the useful output of a red-team.

### Scope boundary — attack 1 vs a *refusing* witness (future 5th row)

Attack 1's "a second history is unforgeable" is proven against the **math** (root
divergence → `verify_checkpoint_consistency` RED), **not** against a *refusing*
witness: today's honest witness signs whatever checkpoint it is handed. When the
**stage-2 checkpoint-aware witness** lands, a natural fifth row appears —
*equivocation attempted at submission → refused by the witness itself* — closing
the gap at the submission boundary rather than only at verification time.

---

# Red-team of the config / identity rungs (B5b, RUNG 2+)

**What "rung 2+" is here.** The rungs stacked ON TOP of the signed/witnessed
ledger:

- **B2 — config cross-check** (`output_cross_check.check_output_against_config`):
  a typed SEAM plus a deliberately *trivial* token-rate / output-shape baseline,
  sitting beside the advertised-vs-served reconciliation
  (`advertisement.reconcile_advertised_vs_served`).
- **B3 — self-measured binary attestation**
  (`plugins/capsule-producer/src/runtime_attest.rs`): the node hashes and signs
  its own executable, labeled `self_measured`.
- **B4 — owner->node binding** (`node_ownership.recheck_ownership_validity`): an
  opt-in, self-asserted `SignedNodeOwnership` cert bound into serving capsules.

**Method** is identical to B5a: each attack is backed by a runnable harness —
[`tests/test_redteam_rung2.py`](../tests/test_redteam_rung2.py) (config +
owner-binding) and
[`plugins/capsule-producer/tests/redteam_rung2_self_measured.rs`](../plugins/capsule-producer/tests/redteam_rung2_self_measured.rs)
(binary attestation) — against real throwaway capsule material, with the same
**caught / labeled / residual (uncaught)** vocabulary.

Run the evidence:

```
python3 -m pytest tests/test_redteam_rung2.py -v
cargo test --manifest-path plugins/capsule-producer/Cargo.toml --test redteam_rung2_self_measured
```

**The headline finding.** Model-id spoof, quant swap, and hardware fake
**LARGELY SUCCEED** against the current prototype — *by design*. The config claim
is **self-reported**, so a node that lies *consistently* (same lie in the
advertisement AND in the served record) reconciles CLEAN:
`reconcile_advertised_vs_served` compares two self-attested claims from **one
party**, and the trivial baseline reads output *plausibility* (rate/shape), never
*identity* or *quality*. This tells us the config-cross-check approach cannot, on
its own, survive an economically-motivated spoof: the real, per-(model, quant,
hardware) statistical reference model is the needed follow-on, and even that is
only probabilistic. **Owner-binding attacks, by contrast, are CAUGHT/LABELED —
B4 holds** (cryptographic self-signature over a domain-tagged canonical claim).

## Weak-links table — rung 2+

| # | Attack | Mechanism | Outcome | Evidence (test) | What closes it |
|---|--------|-----------|---------|-----------------|----------------|
| 5 | **Model-id spoof** | Declare model X in the sealed config claim while the exchange actually served model Y. | **residual (uncaught)** — *by design* | `test_attack5_model_spoof_reconciles_clean_when_lie_is_consistent`, `test_attack5_baseline_crosscheck_cannot_see_model_identity` | The claim is **self-reported**: the node repeats the same lie in the advertisement AND the served record, so reconcile returns `match` (it compares two claims from ONE party — the `advertisement_self_signed` caveat names exactly this). B2's baseline reads rate/shape and gives the *identical* direction for a 3B vs a 70B claim — it never consults `model_id`. Closed by a **counterparty/member-signed discovery note** (two independently-held claims, TRUST-MODEL §9.1) or a **real statistical model** that fingerprints output to a model family. |
| 6 | **Quant swap** | Claim Q8 (high fidelity) but serve Q4 (degraded/cheaper). | **residual (uncaught)** | `test_attack6_quant_swap_reconciles_clean_when_consistent`, `test_attack6_baseline_does_not_flag_a_faster_degraded_quant` | Same self-report gap for the reconciliation. The trivial baseline never inspects output **quality** — the *only* thing distinguishing Q4 from Q8 — and a faster degraded Q4 stays comfortably inside the wide tokens/sec band, so the baseline actually **RAISES** confidence on a quality-degraded serve. This is the finding: the trivial baseline cannot survive a quant swap. Closed by the **real statistical reference model** (expected output distribution per model/quant) — future work, explicitly out of scope. |
| 7 | **Hardware fake** | Claim a better GPU / more VRAM (e.g. H100/80GB) than actually used. | **residual (uncaught)**; only an *absurd* rate is **labeled** | `test_attack7_hardware_fake_reconciles_clean_when_consistent`, `test_attack7_baseline_band_is_too_coarse_to_catch_a_plausible_hw_fake`, `test_attack7b_only_a_physically_absurd_rate_trips_the_coarse_band` | Self-reported ⇒ reconcile is clean. The ONLY lever is tokens/sec-vs-claimed-hardware and it is **coarse**: two hardware *kinds* (`soc` / `discrete_gpu`) and very wide bands, so a merely-exaggerated GPU stays in-band and RAISES. It flags **only** a physically impossible rate (e.g. 5,000,000 tok/s claimed on-device) → that extreme is LABELED (lowers). Closed by a **real per-(model,quant,hardware) reference distribution** — future work. |
| 8 | **Binary tamper (self-measured)** | A compromised/running binary signs the SHA-256 of a *pristine* decoy copy on disk instead of its own tampered bytes. | **residual (uncaught)**, **labeled** `self_measured` | `redteam_rung2_self_measured.rs::attack9_self_measurement_signs_a_pristine_decoy_residual`, `…::attack9b_attestation_from_a_foreign_key_is_caught` | Self-measurement has no root of trust beneath the measurer: the decoy attestation carries a real hash, a valid node-key signature, and the honest `self_measured` label — a verifier cannot tell the hashed file was a decoy. The rung *does* bind the hash to the **node key** (a foreign-key attestation is CAUGHT), but never to the RUNNING bytes. Closed only by an **independent measurer beneath the process**: `os_measured` (IMA/dm-verity, code-signing enforcement) or `tee_measured` (a TEE measuring into a hardware register before exec). |
| 9 | **Owner-binding: forge / expire / cert-swap** | Present a `SignedNodeOwnership` that is signature-forged, expired, or swapped from another node. | **caught** | `test_attack8a_forged_signature_is_caught_and_never_cited_live`, `test_attack8b_expired_cert_is_caught_and_not_bound`, `test_attack8c_cert_swapped_onto_a_different_node_is_caught`, `test_attack8e_absent_cert_is_never_fabricated_into_an_owner` | **B4 holds.** `recheck_ownership_validity` re-verifies the owner's own Ed25519 signature over a domain-tagged canonical claim (forgery → red), the expiry (stale cert → red), and the `node_endpoint_id` inside the signed claim (cert-swap → red). An invalid cert is marked `owner_status="invalid"` and **never cites the identity capsule**; an absent cert degrades to `owner_status="absent"` and is **never fabricated** into an owner. |
| 10 | **Owner-binding: key-substitution impersonation** | Keep owner A's `owner_id` string but embed + sign with the ATTACKER's key. | **labeled** | `test_attack8d_key_substitution_owner_id_still_bound_to_the_signing_key` | The cert is internally consistent so recheck passes — but it binds to the **attacker's KEY**, and the `identity_limitation` caveat (carried into every record whenever a cert is present) states B4 confirms the signature is by the embedded key yet **cannot** prove `owner_id` is a real party. The `owner_id` label is self-asserted, never presented as externally verified. This is the documented honest-gap of the opt-in self-asserted layer; closed by a **third-party-issued credential / trusted root** (out of scope). |

## The shape of the rung-2+ residuals

The rung-1 residual was **coverage** (can't prove the whole history was logged).
The rung-2+ residuals are a different family: **self-report** and **root-of-trust**.

- **Attacks 5–7 (self-report).** The config claim — model, quant, hardware — is
  written by the party being checked, on *both* sides of every offline artifact.
  Reconciliation between two of that party's own claims can only catch an
  *inconsistent* liar, never a consistent one; the trivial baseline reads
  plausibility, not identity or quality. The load-bearing lesson: the
  config-cross-check APPROACH is a plausibility read, and the real value only
  arrives with (a) an **independently-held counterparty claim** (two parties, not
  one) and/or (b) a **real statistical reference model**. Both are future work,
  and the seam (`OutputCrossChecker` Protocol) exists precisely so the real model
  drops in without a caller change.
- **Attack 8 (root-of-trust).** Self-measurement is honest up to — and only up to
  — an independent measurer beneath it. The residual is closed by moving the
  measurement below the process (`os_measured` / `tee_measured`), not by anything
  the process can do to itself.
- **Attacks 9–10 (owner binding) are the CAUGHT/LABELED result** and the
  reassuring one: cryptographic binding to a key is real and holds against
  forgery, expiry, and cert-swap; the only residual is the *human-label*
  limitation (owner_id is self-asserted), which B4 already carries as a permanent
  caveat rather than hiding.

The honest summary: **rung 2 buys plausibility and honest labels, not proof, for
the config claim** — a consistent model/quant/hardware liar succeeds today, and
that finding is the argument for building the real statistical model next — while
**the owner binding buys real cryptographic accountability for the signing key**,
with its self-asserted-identity ceiling stated in-band, not concealed.
