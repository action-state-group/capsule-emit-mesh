<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Rung 1 — the transport/ledger red-team (B5a) — is in REDTEAM-RUNG1.md. -->

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
