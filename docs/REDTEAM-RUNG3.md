<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Rung 1 (transport/ledger, B5a) is REDTEAM-RUNG1.md; rung 2+ (config/identity/
     self-measured binary attestation, B5b) is REDTEAM-RUNG2.md. -->

# Red-team of the independent-measurer rungs (RUNG 3)

**What "rung 3" is here.** The rungs that move binary/model measurement OFF
the process being measured and BELOW it, closing the residual RUNG2 attack 8
(`docs/REDTEAM-RUNG2.md`) named explicitly: self-measurement has no root of
trust beneath the measurer, so a root-compromised host can sign a decoy hash
under the honest `self_measured` label and a verifier cannot tell the
difference.

- **Rung 3a — `os_measured`** (`plugins/capsule-producer/src/runtime_attest.rs`):
  on macOS, the KERNEL (AMFI) independently computes and validates the
  running process's code-directory hash (cdhash) at `exec`, read via
  `csops(2) CS_OPS_CDHASH` and bound into the same signature as the
  self-measured digest. **This section's findings cover rung 3a.**
- **Rung 3c — `tee_measured`** (`plugins/capsule-producer/src/tee_attest.rs`
  + `tee_verify.rs`): a TEE — here, an Intel TDX Confidential VM — measures
  MRTD/RTMR[0..3] into hardware registers before the guest OS or serving
  process runs, and produces a hardware-signed quote a verifier checks
  against Intel's DCAP PKI. **This section covers rung 3c only.**

## Rung 3a — `os_measured`

**Rung 3a method.** Each attack below calls
`capsule_producer::runtime_attest::measure_self` for real, on this
Apple-Silicon lab host (SIP enabled) — a REAL kernel query via `csops(2)` and
`csr_get_active_config()`, not a simulated code path. Harness:
[`plugins/capsule-producer/tests/redteam_rung3_os_measured.rs`](../plugins/capsule-producer/tests/redteam_rung3_os_measured.rs),
with the same **caught / labeled / residual (uncaught)** vocabulary as the
other red-team docs. These attacks are macOS-only by construction (the kernel
measurer this rung reads does not exist elsewhere); `runtime_attest.rs`'s own
portable unit test (`kernel_measurement_gracefully_absent_off_macos`) covers
the graceful-fallback contract on other platforms instead.

Run the evidence:

```
cargo test --manifest-path plugins/capsule-producer/Cargo.toml --lib runtime_attest
cargo test --manifest-path plugins/capsule-producer/Cargo.toml --test redteam_rung3_os_measured
```

**Rung 3a headline finding.** The rung-2 attack that succeeded — a
compromised process pointing its self-measurement at a pristine decoy file
and signing that hash instead of its own — has **no equivalent producer**
under `os_measured` (attack 17): the kernel cdhash is bound to the CALLING
PID, not to any path the process supplies, so there is no `os_measured`
function a decoy path could even be handed to. And because the signature
binds the self-measured digest AND the kernel cdhash JOINTLY into one
message, splicing a genuine cdhash onto a false digest — or vice versa — is
caught even as a pure record-tampering attempt, independent of the
structural argument. The residual that remains is the same SHAPE as rung
3c's: the root of trust relocates rather than disappears, here to **SIP
being enabled** and **a non-root attacker** — both stated in-band in every
`os_measured` record, never assumed silently.

## Weak-links table — rung 3a (`os_measured`)

| # | Attack | Mechanism | Outcome | Evidence (test) | What closes it / residual |
|---|--------|-----------|---------|-----------------|----------------------------|
| 17 | **Decoy relabel under `os_measured`** (the rung-2 attack-9 move, retried) | Point the measurement at, or relabel a record to claim, a pristine decoy file/digest while a different binary actually runs. | **caught / upgraded** | `attack17_decoy_relabel_under_os_measured_is_caught_by_joint_signature` | Structurally: `measure_self` is the only `os_measured` producer and is bound to the CALLING PID, not a path — there is no decoy-capable `os_measured` function to attack (`measure_path` still exists and is still exploitable exactly as rung 2 documented, but it can never produce `os_measured`). Cryptographically: the signature binds `binary_sha256:cdhash` jointly, so relabeling either field — including a genuine cdhash spliced onto a false digest, or vice versa — breaks verification. Mutation-tested: reverting to a digest-only signature flips this test to failure. |
| 18 | **Ad-hoc / unsigned binary** | A locally `cargo build`-produced binary carries no Developer-ID certificate, no notarization, no library-validation entitlement — only an ad-hoc linker signature. | **labeled** | `attack18_ad_hoc_signing_strength_is_labeled_not_silently_trusted` | `os_measured` is still produced (an independent measurer WAS consulted — the kernel), but `ad_hoc_signature=true` and `signing_authority="unknown_local_or_ad_hoc"` ride in the record, and the in-band `context` names the missing Developer-ID/notarization explicitly and states this is NOT `tee_measured`. Never silently presented as a stronger claim than it is. |
| 19 | **Root + SIP-disabled** | A root attacker disables SIP, which lets them bypass AMFI's enforcement — the precondition the entire rung depends on. | **residual (uncaught), named** | `attack19_root_and_sip_off_is_the_named_residual_not_silently_assumed` | Not live-exploited here (destructive, out of scope on the lab host). The record instead carries the LIVE `sip_enabled` bit (real, this host, currently `true`) and the in-band `context` explicitly names the root/SIP-off boundary and states `tee_measured` as the only closing rung — never silently assumed. Closed only by `tee_measured` (rung 3c, below — hardware-rooted), not by anything `os_measured` itself can do. |

## The shape of the rung-3a residual

Rung 2's residual was **root-of-trust below the process** — self-measurement
cannot see below itself. Rung 3a moves the root of trust to the KERNEL
(AMFI), which closes that specific gap (attack 17) the same way rung 3c
closes it with hardware — but, exactly as with rung 3c, a root of trust never
disappears, it relocates to whatever authenticates the NEW measurer. Here
that is **SIP enforcement** (AMFI's signature-validity checks at `exec` only
run because SIP prevents a local root user from disabling them) plus **the
binary's own signing strength** (an ad-hoc signature proves the kernel
validated SOME signature at `exec`, not that a trusted third party vouched
for the code). Both residual/labeled rows above are honest restatements of
that: this rung proves "the kernel independently measured this exact running
binary's cdhash, under SIP, for a signature of the stated strength" — it does
**not** prove "no local root attacker exists" or "a trusted authority signed
this code," because both are outside what a kernel-level, software-only
measurer can see. A deployment that needs that stronger assurance moves to
`tee_measured` (rung 3c, below) — hardware-rooted and immune to a
root-compromised OS in a way no software measurer, including this one, can
be.

**The honest summary — rung 3a:** this rung buys real accountability for
WHICH BYTES ran — a compromised process can no longer sign a decoy's hash and
have it pass as kernel-attested — while the STRENGTH of that accountability
remains bounded by SIP being enabled, the attacker being non-root, and the
binary's actual signing authority, all three stated in-band rather than
concealed. `self_measured` remains the honest floor this rung upgrades from,
not a mode this rung ever silently falls back to without saying so.

---

## Rung 3c — `tee_measured`

**Scope note.** Rung 3c's SPEC + VERIFIER (record shape, quote parser, local
DCAP cert-chain/signature verification, optional Intel Trust Authority token
path) is hardware-independent and covered below with full adversarial
evidence. The PRODUCER leg (obtaining a REAL quote via Linux configfs-TSM on
a provisioned Intel TDX node) is HW-gated and out of scope for this
document's evidence — see `plugins/capsule-producer/src/tee_attest.rs`
module docs for why a fabricated quote is never produced on hosts without
the hardware (this codebase's Mac development fleet tops out at
`os_measured`; that ceiling is stated honestly rather than hidden — see
README "Field mapping").

**Method** is identical to B5a/B5b: each attack is backed by a runnable
harness —
[`plugins/capsule-producer/tests/redteam_rung3_tee_measured.rs`](../plugins/capsule-producer/tests/redteam_rung3_tee_measured.rs)
— against a REAL synthetic PCK-style cert chain and REAL `p256`/`p384`
signatures (not placeholder bytes), with the same **caught / labeled /
residual (uncaught)** vocabulary as the other red-team docs. The chain and
keys are test-generated (not Intel key material); the cryptographic checks
exercised are the production `tee_verify` code path.

Run the evidence:

```
cargo test --manifest-path plugins/capsule-producer/Cargo.toml --test redteam_rung3_tee_measured
```

**The headline finding.** The rung-2 attack that succeeded — a
root-compromised host signing a decoy measurement under an honest label —
is **CAUGHT** here (attack 16). There is no code path in the TDX guest that
can make the CPU's attestation key sign an MRTD/RTMR it did not itself
measure: any post-signing edit to the measured bytes invalidates the quote
signature, because the signature is made by hardware beneath the process,
not by the process. This is the concrete evidence for
`tee_attest.rs`'s module-doc claim that a root-compromised host "cannot
forge it the way it can forge a `self_measured` attestation." The trust
root does not disappear, though — it MOVES, from "trust the process" to
"trust Intel's DCAP PKI + TCB freshness," and the residual rows below name
that new ceiling explicitly, the same way rung 2 named the old one.

## Weak-links table — rung 3c (`tee_measured`)

| # | Attack | Mechanism | Outcome | Evidence (test) | What closes it / residual |
|---|--------|-----------|---------|-----------------|----------------------------|
| 11 | **Quote replay across capsules** | Present a genuinely valid, hardware-signed quote from exchange A as evidence for a DIFFERENT exchange B (same node). | **caught** | `attack11_quote_replayed_across_a_different_capsule_is_caught_by_binding` | `verify_binding` recomputes REPORTDATA = `SHA-512(domain_tag \|\| capsule_digest \|\| nonce)` from B's OWN digest/nonce; a quote minted binding A's digest cannot match. |
| 12 | **Quote replay with a stale nonce** | Same exchange digest, but the requester's nonce rotated (a fresh request for the same logical exchange presented with an old quote). | **caught** | `attack12_quote_replayed_with_a_stale_nonce_is_caught_by_binding` | Same binding mechanism as #11 — REPORTDATA mixes in the nonce, not just the digest, so nonce rotation alone also breaks a replayed quote. |
| 13 | **Cert chain rooted at an attacker-controlled CA** | The node runs its own CA, issues itself a structurally PCK-shaped cert chain, and signs a quote with it — bit-for-bit the same shape as a real DCAP quote. | **caught** | `attack13_cert_chain_rooted_at_attacker_controlled_ca_is_caught` | `verify_dcap_quote` requires the chain's terminal certificate to match the OPERATOR-SUPPLIED [`TrustedRoot`] **exactly** (byte-equal DER). An attacker-issued root never matches Intel's — and this library never bundles a pinned "real" Intel root itself (see `tee_verify` module docs: a wrong hardcoded root would be worse than none), so the operator's own configuration is the thing an attacker would have to compromise, not this code. |
| 14 | **Forged QE report signature (no valid PCK cert)** | An attacker without any real PCK certificate tries to vouch for an attestation key by signing the QE report with an arbitrary key. | **caught** | `attack14_forged_qe_report_signature_without_a_valid_pck_cert_is_caught` | `verify_dcap_quote` checks `qe_report_sig` against the PCK LEAF certificate's own key specifically — a signature by any other key fails verification. |
| 15 | **Attestation key not bound into the vouched-for QE report** | The PCK leaf legitimately signs a QE report — but for a DIFFERENT attestation key than the one that actually signs the quote (key substitution after the PCK vouch). | **caught** | `attack15_attestation_key_not_bound_into_qe_report_is_caught` | The QE report's trailing field must equal `SHA-256(attest_pub_key \|\| qe_auth_data)` for the key PRESENT in the quote. Substituting the key breaks that binding even though `qe_report_sig` is a genuine PCK signature over *some* report. |
| 16 | **Post-signing measurement tamper (THE HEADLINE — RUNG2 #8's analogue)** | Flip one byte of MRTD after the quote is signed, simulating a host trying to present a measurement the TDX module never produced — the rung-2 move that SUCCEEDED against `self_measured`. | **caught** | `attack16_headline_post_signing_measurement_tamper_is_caught_where_self_measured_was_not` | Unlike self-measurement, the signer is the TDX module, not the guest process — there is no path in the guest to make the attestation key sign a measurement it did not observe. Any edit to `header\|\|body` after signing invalidates `quote_sig`. This is the rung-2 residual, closed. |
| — | **TCB staleness / cert revocation (RESIDUAL 1)** | A platform whose TCB is out of date or whose PCK cert has since been REVOKED still produces a quote that is structurally and cryptographically perfect — the signature chain and REPORTDATA binding this module checks are unaffected by TCB/revocation state. | **residual (uncaught), labeled** | `residual1_offline_verifier_cannot_see_tcb_staleness_or_revocation` | Requires a LIVE query against Intel PCS TCB-info/QE-identity/CRL collateral, or routing through Intel Trust Authority's live policy evaluation — this offline verifier deliberately performs neither (see `tee_verify` module docs). A deployment that needs revocation-aware verification must add that live check; it is a distinct, addressable gap, not silently hidden inside an `Ok(())`. |
| — | **ITA token claim freshness (RESIDUAL 2)** | `verify_ita_token` proves a token was signed by the holder of the operator-supplied ITA key and decodes its claims — it does NOT evaluate whether those claims assert a fresh/passing verdict. A validly-signed but stale-verdict token still verifies. | **residual (uncaught), labeled** | `residual2_ita_token_verifies_signature_shape_only_not_claim_freshness` | `verify_ita_token`'s contract is authenticity of the TOKEN, not truth/freshness of its CONTENT — the caller must inspect the decoded claims (e.g. a verdict/expiry field ITA includes) itself. Named explicitly so no caller mistakes "the JWT verifies" for "the platform is currently trustworthy." |

## The shape of the rung-3c residual

Rung 2's residual was **root-of-trust below the process** — self-measurement
cannot see below itself. Rung 3c moves the root of trust to the TDX
module/CPU, which closes that specific gap (attack 16) — but a root of trust
is never absolute; it relocates to whatever authenticates the NEW measurer.
Here that is **Intel's DCAP PKI** (the SGX/TDX root CA and the PCK
certificate provisioning chain) plus **TCB currency** (has this platform's
microcode/firmware been patched against known issues, and is its cert still
valid). Both residuals above are honest restatements of that: this module
verifies "a valid TDX module signed this measurement, for this key, for this
cert chain, rooted at whatever root the OPERATOR configured" — it does
**not** verify "Intel's PKI is uncompromised" or "this specific platform's
TCB is current," because both require a live network call this offline
verifier intentionally does not make. A deployment that needs that assurance
adds it as an explicit, visible extra step (PCS collateral fetch, or full
trust in ITA's live verdict) — never folded silently into this module's
`Ok(())`.

**The honest summary:** rung 3c buys real hardware-rooted accountability for
the MEASUREMENT itself — a root-compromised host genuinely cannot forge
MRTD/RTMR the way it could forge a `self_measured` hash — while the
FRESHNESS of that hardware root's trustworthiness (TCB state, revocation)
remains an explicit, named, closable-but-not-yet-closed gap, exactly the way
`self_measured`'s ceiling was stated in-band rather than concealed.
