// SPDX-License-Identifier: Apache-2.0
//! Rung 3a — adversarial red-team of the `os_measured` rung
//! (`capsule_producer::runtime_attest`'s kernel-cdhash path).
//!
//! **What rung 3a is.** An independent measurer BENEATH the process on macOS:
//! the kernel (AMFI) computes and validates the running process's
//! code-directory hash (cdhash) at `exec`, via `csops(2) CS_OPS_CDHASH` — a
//! value the process does not compute and cannot redirect (it is bound to the
//! calling PID, not to any path the process supplies). This is the rung that
//! is supposed to close RUNG2 attack 8 (`docs/REDTEAM-RUNG2.md`) — a
//! compromised process signing the hash of a pristine decoy under the honest
//! `self_measured` label. This file turns that claim into executable
//! evidence, the same way `redteam_rung2_self_measured.rs` did for B3 and
//! `redteam_rung3_tee_measured.rs` does for rung 3c.
//!
//! **Method — REAL kernel, no mock.** Every attack below calls
//! `capsule_producer::runtime_attest::measure_self`, which on this
//! Apple-Silicon lab host (SIP enabled) queries the REAL kernel via `csops(2)`
//! and `csr_get_active_config()` — not a simulated code path. Outcome
//! vocabulary matches the other red-team docs:
//!   CAUGHT   — rejected.
//!   LABELED  — accepted but the gap is named honestly (a verifier can see it).
//!   RESIDUAL — succeeds / cannot be exercised live; the closing rung is named.
//!
//! These tests are macOS-only by construction (the kernel measurer this rung
//! reads does not exist elsewhere) — gated with `#[cfg(target_os = "macos")]`
//! rather than silently skipped: on non-macOS CI they simply do not compile
//! into the test binary, and `runtime_attest`'s own portable unit test
//! (`kernel_measurement_gracefully_absent_off_macos`) covers the graceful-
//! fallback contract there instead.
//!
//! Run: `cargo test --manifest-path plugins/capsule-producer/Cargo.toml --test redteam_rung3_os_measured`

#![cfg(target_os = "macos")]

use capsule_producer::keys::KeyPair;
use capsule_producer::runtime_attest::{measure_self, MeasurementClass};

/// ATTACK 17 — DECOY ATTEMPT UNDER `os_measured` (the rung-2 attack-9 move,
/// retried against the stronger grade).
///
/// Rung 2's residual: a compromised process points `measure_path` at a
/// PRISTINE decoy file and signs ITS hash — internally perfect, honestly
/// labeled `self_measured`, and a verifier cannot tell. Rung 3a closes this
/// two ways at once:
///
///   1. **Structural**: there is no `os_measured` producer that takes a path.
///      [`measure_self`] is the ONLY producer, and it is bound to the
///      CALLING PROCESS's own PID — an attacker cannot pass a decoy path to
///      the kernel query the way `measure_path` lets them pass one to the
///      self-hasher. (`measure_path` itself still exists and is still
///      exploitable exactly as rung 2 documented — see
///      `measure_path_never_produces_kernel_signing_even_on_macos` in
///      `runtime_attest.rs` — but it can NEVER produce `os_measured`, so that
///      specific residual is UNREACHABLE via this rung.)
///   2. **Cryptographic**: even granting the attacker a genuine `os_measured`
///      record (real cdhash of whatever is ACTUALLY running), relabeling its
///      `binary_path`/`binary_sha256` to claim it measured a different
///      (pristine-looking) file breaks the joint signature — the rung binds
///      the self-reported digest AND the kernel cdhash into ONE signed
///      message.
///
/// -> CAUGHT / upgraded. The rung-2 residual has no equivalent here.
#[test]
fn attack17_decoy_relabel_under_os_measured_is_caught_by_joint_signature() {
    let keys = KeyPair::generate();
    let genuine = measure_self(&keys, "2026-08-31T00:00:00Z".to_string())
        .expect("current_exe is measurable in a cargo test binary");
    assert_eq!(
        genuine.measurement_class,
        MeasurementClass::OsMeasured,
        "this lab host must produce a real os_measured attestation"
    );
    assert!(genuine.verify_signature(&keys.verifying_key()));

    // The attacker's move: keep the REAL kernel cdhash (they cannot forge or
    // redirect it) but relabel the self-reported path/digest to look like a
    // pristine decoy — exactly rung 2 attack 9's trick, replayed here.
    let mut relabeled = genuine.clone();
    relabeled.binary_path = "/Applications/PristineDecoy.app/Contents/MacOS/decoy".to_string();
    relabeled.binary_sha256 = "ab".repeat(32); // a plausible-looking, but FALSE, digest

    assert!(
        !relabeled.verify_signature(&keys.verifying_key()),
        "relabeling the self-reported digest while keeping the real cdhash \
must break the joint signature — CAUGHT"
    );

    // The SHARPER, cdhash-only variant — this is the case that specifically
    // exercises the joint-signature upgrade rather than protection inherited
    // from self_measured: leave the self-reported digest EXACTLY as signed
    // (a genuinely-computed hash), and swap ONLY the accompanying cdhash for
    // one borrowed from a different, legitimate measurement. Under a
    // digest-only signature (the pre-rung-3a scheme) this substitution would
    // NOT be caught, because the signed message never mentioned the cdhash at
    // all — a verifier reading `code_directory_hash` next to a validly-signed
    // digest could be shown any cdhash the attacker likes.
    let mut cdhash_swapped = genuine.clone();
    let mut k = cdhash_swapped.kernel_signing.clone().expect("os_measured");
    let real_cdhash = k.cdhash.clone();
    k.cdhash = "ff".repeat(20); // a different, "borrowed" cdhash
    assert_ne!(k.cdhash, real_cdhash);
    cdhash_swapped.kernel_signing = Some(k);
    assert!(
        !cdhash_swapped.verify_signature(&keys.verifying_key()),
        "swapping ONLY the cdhash, with the digest left genuinely signed, must \
STILL be caught — this is what proves the signature is JOINT over digest+cdhash, \
not digest-only with cdhash riding along unauthenticated. A digest-only-signing \
mutant would let this exact substitution through — CAUGHT here"
    );

    // For contrast: `measure_path` (rung 2's producer) is STILL exploitable
    // exactly as documented, and it NEVER produces os_measured no matter what
    // path it is pointed at — confirming there is no decoy-capable os_measured
    // producer to attack in the first place.
    let dir = std::env::temp_dir().join(format!("rung3a-decoy-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("tmp dir");
    let pristine = dir.join("pristine-decoy");
    std::fs::write(&pristine, b"the good, audited bytes").expect("write pristine");
    let decoy_att = capsule_producer::runtime_attest::measure_path(
        &keys,
        &pristine,
        "2026-08-31T00:00:00Z".to_string(),
    )
    .expect("pristine file is measurable");
    assert_eq!(decoy_att.measurement_class, MeasurementClass::SelfMeasured);
    assert!(
        decoy_att.kernel_signing.is_none(),
        "the only decoy-capable producer (measure_path) never claims os_measured"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// ATTACK 18 — AD-HOC / UNSIGNED BINARY (signing-strength honesty).
///
/// A locally `cargo build`-produced binary carries no Developer-ID
/// certificate, no notarization, no library-validation entitlement — only an
/// ad-hoc, linker-applied signature. `os_measured` must NOT silently present
/// this as a stronger claim than it is: the `ad_hoc_signature` caveat must be
/// `true` and stated IN-BAND, and the record must never read as
/// `tee_measured` (no hardware root is involved here at all).
///
/// -> LABELED. The rung correctly separates "is there an independent
/// measurer" (yes — `os_measured` is still produced) from "how strong is the
/// signer" (ad-hoc — carried as an explicit caveat, not hidden).
#[test]
fn attack18_ad_hoc_signing_strength_is_labeled_not_silently_trusted() {
    let keys = KeyPair::generate();
    let att = measure_self(&keys, "2026-08-31T00:00:00Z".to_string()).expect("measurable");
    let kernel = att.kernel_signing.as_ref().expect("os_measured on this host");

    assert!(
        !kernel.platform_binary,
        "a cargo test binary is never an Apple platform binary"
    );
    assert!(
        kernel.ad_hoc_signature,
        "a local cargo build must be labeled ad-hoc, never presented as stronger"
    );
    assert_eq!(kernel.signing_authority, "unknown_local_or_ad_hoc");

    let v = att.to_value();
    // Still upgraded to os_measured — an independent measurer WAS consulted.
    assert_eq!(v["measurement_class"], "os_measured");
    assert_eq!(v["ad_hoc_signature"], true);
    let context = v["context"].as_str().expect("context string");
    assert!(
        context.to_lowercase().contains("ad-hoc") || context.to_lowercase().contains("ad hoc"),
        "ad-hoc caveat must be stated in-band: {context}"
    );
    assert!(
        context.contains("Developer-ID") || context.contains("notarization"),
        "the specific missing signing strength must be named, not just \"weak\": {context}"
    );
    assert!(
        !context.contains("tee_measured is confirmed") && context.contains("NOT tee_measured"),
        "must never let os_measured read as tee_measured: {context}"
    );
}

/// ATTACK 19 — ROOT + SIP-DISABLED (the named residual, not live-exploited).
///
/// `os_measured`'s entire argument is AMFI enforcing signature validity at
/// `exec`, under SIP. A root attacker who disables SIP can bypass AMFI and
/// therefore this rung's guarantee — but this test does NOT (and must not)
/// actually disable SIP on the lab host to "prove" it; that would be
/// destructive and is explicitly out of scope. Instead this asserts the
/// record HONESTLY carries the precondition it depends on: the live
/// `sip_enabled` bit (real, this host, currently `true`) and an explicit
/// in-band statement that root+SIP-off is the closing boundary — never
/// silently assumed.
///
/// -> RESIDUAL (named boundary). Closed only by `tee_measured` (rung 3c,
/// hardware-rooted — see `docs/REDTEAM-RUNG3.md`'s rung-3c section), never by
/// anything `os_measured` itself can do.
#[test]
fn attack19_root_and_sip_off_is_the_named_residual_not_silently_assumed() {
    let keys = KeyPair::generate();
    let att = measure_self(&keys, "2026-08-31T00:00:00Z".to_string()).expect("measurable");
    let kernel = att.kernel_signing.as_ref().expect("os_measured on this host");

    // Ground truth for this lab host, per the task brief: SIP is enabled.
    assert!(
        kernel.sip_enabled,
        "this lab host is documented SIP-enabled; the live check must agree"
    );

    let context = att.to_value()["context"]
        .as_str()
        .expect("context string")
        .to_string();
    assert!(context.contains("SIP"), "SIP precondition must be named: {context}");
    assert!(
        context.contains("NON-ROOT") || context.to_lowercase().contains("root"),
        "the root-attacker boundary must be named: {context}"
    );
    assert!(
        context.contains("tee_measured"),
        "the closing rung must be named inline, not left implicit: {context}"
    );
    assert!(
        context.contains("residual"),
        "the record must call this what it is — a residual, not a proof: {context}"
    );
}
