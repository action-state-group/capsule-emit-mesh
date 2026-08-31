// SPDX-License-Identifier: Apache-2.0
//! B5b — adversarial red-team of the self-measured binary attestation rung (B3,
//! `runtime_attest.rs`). This is a RUNG-2 attack: it does not touch the ledger.
//!
//! The rung is honestly labeled `self_measured`: the process hashes its OWN
//! on-disk executable and signs the digest with the node key. Its module docs
//! already state the ceiling — "does NOT prove the running binary was un-tampered
//! before it hashed itself." This test turns that stated weakness into
//! EXECUTABLE evidence for the findings table (`docs/REDTEAM-RUNG1.md`).
//!
//! Outcome vocabulary (matches the Python harness):
//!   CAUGHT   — rejected.
//!   LABELED  — accepted but named honestly so a verifier sees the degradation.
//!   RESIDUAL — succeeds; the rung has no handle. Closing rung named inline.

use capsule_producer::keys::KeyPair;
use capsule_producer::runtime_attest::{measure_path, MeasurementClass};

/// ATTACK 9 — PRISTINE-COPY SWAP (the self-measurement residual).
///
/// A compromised/running binary can measure and sign the hash of a DIFFERENT,
/// pristine file rather than its own tampered bytes. Because measurement has no
/// root of trust beneath the measurer, the produced attestation is
/// indistinguishable from an honest one: it carries a real SHA-256, a valid
/// node-key signature, and the `self_measured` label — yet the digest is of the
/// pristine decoy, not of whatever bytes are actually executing.
///
/// -> RESIDUAL (uncaught by self-measurement). The signature VERIFIES and the
/// record is internally perfect; nothing in the rung binds the hashed file to
/// the bytes that actually ran. Closed only by an independent measurer beneath
/// the process: `os_measured` (IMA/dm-verity, code-signing enforcement) or
/// `tee_measured` (a TEE that measures into a hardware register before exec).
#[test]
fn attack9_self_measurement_signs_a_pristine_decoy_residual() {
    let keys = KeyPair::generate();
    let dir = std::env::temp_dir().join(format!("b5b-attest-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("tmp dir");

    // The "pristine" binary the attacker WANTS to be seen as running.
    let pristine = dir.join("serving-binary-pristine");
    std::fs::write(&pristine, b"the good, audited serving binary bytes").expect("write pristine");

    // The bytes that are ACTUALLY running (tampered) — never measured, because a
    // compromised process simply points the measurement at the pristine file.
    let tampered = dir.join("serving-binary-tampered");
    std::fs::write(&tampered, b"malicious swapped serving binary bytes").expect("write tampered");

    // The attacker measures the PRISTINE decoy (this is exactly what a compromised
    // `measure_self` would do: resolve/point at a clean copy on disk).
    let att = measure_path(&keys, &pristine, "2026-08-30T00:00:00Z".to_string())
        .expect("pristine file is measurable");

    // 1) The attestation is INTERNALLY PERFECT: real hash of the decoy, valid
    //    signature by the node key, honest-looking self_measured label.
    assert_eq!(att.measurement_class, MeasurementClass::SelfMeasured);
    assert!(
        att.verify_signature(&keys.verifying_key()),
        "the decoy attestation's node-key signature VERIFIES — nothing to reject"
    );

    // 2) It commits to the PRISTINE hash, not the tampered/running bytes.
    use sha2::{Digest, Sha256};
    let pristine_hash = hex::encode(Sha256::digest(b"the good, audited serving binary bytes"));
    let tampered_hash = hex::encode(Sha256::digest(b"malicious swapped serving binary bytes"));
    assert_eq!(att.binary_sha256, pristine_hash, "signed the pristine decoy's hash");
    assert_ne!(
        att.binary_sha256, tampered_hash,
        "the running bytes are NEVER what got hashed — that is the residual"
    );

    // 3) THE RESIDUAL, stated: a verifier holding this capsule sees a valid
    //    self_measured attestation and cannot tell the hashed file was a decoy.
    //    The label is the only honesty — it says self_measured, i.e. trust only
    //    up to an OS/TEE. Closed by os_measured / tee_measured, NOT by this rung.
    let v = att.to_value();
    assert_eq!(v["measurement_class"], "self_measured");
    assert!(
        v["context"].as_str().unwrap().contains("untampered before hashing"),
        "the record must state in-band that it does NOT prove un-tampered running bytes"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// ATTACK 9b — WRONG-KEY SUBSTITUTION IS CAUGHT (the rung's real guarantee).
///
/// The one thing self-measurement DOES bind: the signature is by the node key.
/// An attestation signed by some OTHER key does not verify against the node's
/// verifying key, so a verifier can confirm the SAME node that signed the
/// capsule vouched for the (whatever) hash.
///
/// -> CAUGHT. Bounds where the rung's guarantee is real: it ties the hash to the
/// node key, even though it cannot tie the hash to the RUNNING bytes.
#[test]
fn attack9b_attestation_from_a_foreign_key_is_caught() {
    let node = KeyPair::generate();
    let attacker = KeyPair::generate();
    let dir = std::env::temp_dir().join(format!("b5b-attest-fk-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("tmp dir");
    let bin = dir.join("bin");
    std::fs::write(&bin, b"some binary").expect("write");

    // Attestation produced under the ATTACKER's key.
    let att = measure_path(&attacker, &bin, "2026-08-30T00:00:00Z".to_string()).expect("measurable");

    // A verifier checking against the NODE's key rejects it.
    assert!(
        !att.verify_signature(&node.verifying_key()),
        "an attestation not signed by the node key must NOT verify — CAUGHT"
    );
    // It does verify under its true (attacker) key — proving the check is real,
    // not vacuous.
    assert!(att.verify_signature(&attacker.verifying_key()));

    let _ = std::fs::remove_dir_all(&dir);
}
