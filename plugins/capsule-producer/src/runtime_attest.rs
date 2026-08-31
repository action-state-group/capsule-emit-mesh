//! Runtime / binary attestation rung (task B3): hash the serving binary the
//! node actually runs and record a signed reference to it in the exchange
//! capsule's provenance, shaped like executable code-signing.
//!
//! ## HONESTY GRADE — read this before trusting the rung
//!
//! This attestation is **`self_measured`**: the very process being attested
//! hashes *its own* on-disk executable ([`std::env::current_exe`]) and signs the
//! digest with the node key it already holds. It therefore proves only:
//!
//!   > "a process holding the node key reported *this* SHA-256 for the file it
//!   >  believes is its own executable, at the moment it measured."
//!
//! It does **NOT** prove the running binary was un-tampered before it hashed
//! itself. A compromised binary can compute the hash of a *pristine* copy on
//! disk (or of anything else) and sign that; a binary swapped after `exec` can
//! report the old path's bytes; the OS can hand back a decoy file. Self-
//! measurement has no root of trust below the thing doing the measuring, so it
//! is only trustworthy up to an **independent measurer beneath it** — an OS
//! integrity layer (IMA/dm-verity, code-signing enforcement) or a TEE that
//! measures the binary into a hardware register before it runs. Those would be
//! recorded as `os_measured` / `tee_measured` respectively; this rung is the
//! honest floor, explicitly labeled so no reader mistakes it for either.
//!
//! The [`MeasurementClass`] label is carried IN the signed record itself (not
//! only in these docs), so a verifier reading the capsule sees the honesty
//! grade inline and cannot be told "attested binary" without also being told
//! "self-measured, trust-me-up-to-the-OS".
//!
//! ## Graceful degradation
//!
//! If the running binary's path cannot be resolved or read (some sandboxes and
//! unusual `exec` setups deny [`std::env::current_exe`], or the file was
//! unlinked after launch), the rung records **nothing** — [`measure_self`]
//! returns `None`. Absence of a fact is recorded as absence; a binary
//! attestation is NEVER fabricated (no zero-hash, no placeholder path). The
//! capsule then carries the honest empty `binary_attestation` evidence slot.

use crate::keys::{key_id_of, KeyPair};
use ed25519_dalek::Signer;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

/// How the binary digest in a [`BinaryAttestation`] was obtained — the honesty
/// grade of the rung. Serialized verbatim into the signed record's
/// `measurement_class` field so the grade travels WITH the attestation.
///
/// Only `SelfMeasured` is produced today. `OsMeasured` / `TeeMeasured` are the
/// named future rungs an independent measurer beneath the process would emit;
/// they are declared here so the vocabulary (and the fact that self-measurement
/// is the *weakest* of the three) is legible in this file, not just in docs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MeasurementClass {
    /// The attested process hashed its own executable. Trustworthy only up to
    /// an OS/TEE that independently measures it (see module docs). This is the
    /// weakest grade and the only one this rung emits.
    SelfMeasured,
    /// An OS integrity layer (IMA/dm-verity, code-signing enforcement)
    /// measured the binary independently of the process. NOT emitted yet.
    OsMeasured,
    /// A TEE measured the binary into a hardware register before it ran. NOT
    /// emitted yet.
    TeeMeasured,
}

impl MeasurementClass {
    /// The exact string label carried in the record. `self_measured` is the
    /// deliverable honesty label the task requires; the other two are reserved
    /// for the future independent-measurer rungs.
    pub const fn as_str(self) -> &'static str {
        match self {
            MeasurementClass::SelfMeasured => "self_measured",
            MeasurementClass::OsMeasured => "os_measured",
            MeasurementClass::TeeMeasured => "tee_measured",
        }
    }
}

/// A signed reference to the running serving binary, shaped like executable
/// code-signing: `sha256(binary)` plus an Ed25519 signature over that digest by
/// the node key, carrying its own honesty grade (`measurement_class`).
///
/// Every field is a real measured/derived value — there is no fabricated
/// fallback. When the binary cannot be measured, no `BinaryAttestation` is
/// produced at all (see [`measure_self`]).
#[derive(Clone, Debug)]
pub struct BinaryAttestation {
    /// The honesty grade of this measurement. Today always
    /// [`MeasurementClass::SelfMeasured`] — the node hashed its OWN binary.
    pub measurement_class: MeasurementClass,
    /// Absolute path of the executable that was hashed, as the process resolved
    /// its own `current_exe`. Recorded so a reader knows WHICH file was
    /// measured; it is NOT a claim the path is canonical or un-swappable.
    pub binary_path: String,
    /// Lowercase-hex SHA-256 of the executable's bytes.
    pub binary_sha256: String,
    /// Byte length of the executable that was hashed — a cheap cross-check a
    /// verifier can use alongside the digest.
    pub binary_size_bytes: u64,
    /// Signature algorithm: `ed25519` (the node key's algorithm).
    pub signature_algorithm: String,
    /// Lowercase-hex Ed25519 signature by the node key over the ASCII bytes of
    /// `binary_sha256` (the hex digest string) — the code-signing gesture:
    /// "this node vouches it observed this binary hash". Hex to match every
    /// other digest/id in this codebase (no base64 runtime dep).
    pub signature: String,
    /// `key_id` of the node key that signed — the same 16-hex-char scheme used
    /// across capsule-anchor and this crate's `keys::key_id_of`, so a verifier
    /// can tie the signature to the capsule's signing key.
    pub signer_key_id: String,
    /// When the measurement was taken (ISO-8601 UTC). A self-measurement is a
    /// point-in-time observation, not a standing guarantee.
    pub measured_at: String,
}

impl BinaryAttestation {
    /// Verify this attestation's node-key signature over its own hex digest,
    /// against a candidate verifying key. `true` iff the signature is a valid
    /// Ed25519 signature by `vk` over the ASCII bytes of `binary_sha256`. A
    /// verifier reading a sealed capsule uses this to confirm the node that
    /// signed the capsule is the same node that vouched for the binary hash.
    /// (Malformed signature hex -> `false`, never a panic.)
    pub fn verify_signature(&self, vk: &ed25519_dalek::VerifyingKey) -> bool {
        use ed25519_dalek::Verifier;
        let Ok(sig_bytes) = hex::decode(&self.signature) else {
            return false;
        };
        let Ok(sig_arr): Result<[u8; 64], _> = sig_bytes.try_into() else {
            return false;
        };
        let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);
        vk.verify(self.binary_sha256.as_bytes(), &signature).is_ok()
    }

    /// The evidence-ref JSON object for this attestation, slotted into the
    /// capsule's `evidence_refs.binary_attestation`. The `self_measured` label
    /// rides here (`measurement_class`) AND is echoed by the `type` tag, so the
    /// honesty grade is unmissable in the sealed record.
    pub fn to_value(&self) -> Value {
        json!({
            "type": "binary_attestation",
            // THE honesty label. Explicitly self_measured — see module docs.
            "measurement_class": self.measurement_class.as_str(),
            "digest": self.binary_sha256,
            "digest_alg": "sha256",
            "binary_path": self.binary_path,
            "binary_size_bytes": self.binary_size_bytes,
            "signature": self.signature,
            "signature_algorithm": self.signature_algorithm,
            "signer_key_id": self.signer_key_id,
            "measured_at": self.measured_at,
            // Belt-and-suspenders honesty for a human reading the raw capsule:
            // the trust ceiling stated in-band, not only in the code comments.
            "context": "self-measured: the node hashed its own serving binary; \
trustworthy only up to an OS/TEE that independently measures it. Does NOT prove \
the binary was untampered before hashing.",
        })
    }

    /// The value for the capsule's `compute_attestation.runtime` field: the real
    /// binary digest, labeled with its grade and the runtime name, replacing the
    /// old `0*64` placeholder. Shape `"<sha256>:<class>:<runtime-name>"` keeps
    /// the existing `<hash>:<runtime>` convention while making the grade legible.
    pub fn runtime_field(&self, runtime_name: &str) -> String {
        format!(
            "{}:{}:{}",
            self.binary_sha256,
            self.measurement_class.as_str(),
            runtime_name
        )
    }
}

/// Measure and sign the RUNNING serving binary, self-measured.
///
/// Resolves this process's own executable ([`std::env::current_exe`]), reads and
/// SHA-256-hashes it, and signs the hex digest with the node key. Returns:
///   * `Some(BinaryAttestation)` on success — a real, signed, `self_measured`
///     reference to the binary this node runs.
///   * `None` if the path can't be resolved OR the file can't be read. The rung
///     then degrades gracefully: the capsule records the attestation as ABSENT
///     rather than fabricating a hash or a path.
///
/// `measured_at` is supplied by the caller so it matches the capsule timestamp
/// clock (`timestamp::utc_now_iso8601`) and stays testable.
pub fn measure_self(keys: &KeyPair, measured_at: String) -> Option<BinaryAttestation> {
    // current_exe() can fail (sandbox denies it, /proc unavailable, exe
    // unlinked). Degrade: no attestation, never a fabricated one.
    let path: PathBuf = std::env::current_exe().ok()?;
    measure_path(keys, &path, measured_at)
}

/// The measurement core, split out so a test can point it at a known file
/// instead of the test-runner binary. Same graceful-degradation contract:
/// `None` when the file cannot be read.
pub fn measure_path(
    keys: &KeyPair,
    path: &std::path::Path,
    measured_at: String,
) -> Option<BinaryAttestation> {
    let bytes = std::fs::read(path).ok()?;
    let binary_sha256 = hex::encode(Sha256::digest(&bytes));
    // Code-signing gesture: sign over the ASCII hex digest the record carries,
    // so a verifier signs/verifies exactly the string it reads.
    let signature = keys.signing_key.sign(binary_sha256.as_bytes());
    Some(BinaryAttestation {
        measurement_class: MeasurementClass::SelfMeasured,
        binary_path: path.display().to_string(),
        binary_sha256,
        binary_size_bytes: bytes.len() as u64,
        signature_algorithm: "ed25519".to_string(),
        signature: hex::encode(signature.to_bytes()),
        signer_key_id: key_id_of(&keys.verifying_key()),
        measured_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier};

    /// The rung records the real SHA-256 of the measured file AND carries the
    /// `self_measured` honesty label — in the struct, in the runtime field, and
    /// in the evidence-ref JSON — and the signature verifies under the node key.
    #[test]
    fn measures_hash_and_ships_self_measured_label_and_valid_signature() {
        let keys = KeyPair::generate();
        let tmp = std::env::temp_dir().join(format!("b3-attest-{}", std::process::id()));
        std::fs::write(&tmp, b"fake serving binary bytes").expect("write tmp binary");

        let att = measure_path(&keys, &tmp, "2026-08-30T00:00:00Z".to_string())
            .expect("measurable file yields an attestation");

        // Records the REAL hash of the file (independently recomputed here).
        let expected = hex::encode(Sha256::digest(b"fake serving binary bytes"));
        assert_eq!(att.binary_sha256, expected, "records the real binary hash");
        assert_eq!(att.binary_size_bytes, b"fake serving binary bytes".len() as u64);

        // THE honesty label, in every place it must ship.
        assert_eq!(att.measurement_class, MeasurementClass::SelfMeasured);
        assert_eq!(att.measurement_class.as_str(), "self_measured");
        let v = att.to_value();
        assert_eq!(v["measurement_class"], "self_measured");
        assert_eq!(v["digest"], expected);
        assert_eq!(v["type"], "binary_attestation");
        // The trust ceiling is stated in-band.
        assert!(v["context"]
            .as_str()
            .unwrap()
            .contains("self-measured"));
        assert!(v["context"]
            .as_str()
            .unwrap()
            .contains("untampered before hashing"));
        // Runtime field carries the real hash + the self_measured grade.
        let rt = att.runtime_field("mesh-llm-host-runtime");
        assert!(rt.starts_with(&expected));
        assert!(rt.contains("self_measured"));
        assert!(rt.contains("mesh-llm-host-runtime"));
        assert_ne!(rt, "0".repeat(64) + ":mesh-llm-host-runtime");

        // The signature is a real Ed25519 signature over the hex digest by the
        // node key — the code-signing gesture verifies.
        let sig_bytes: [u8; 64] = hex::decode(&att.signature)
            .expect("hex sig")
            .try_into()
            .expect("64-byte sig");
        let signature = Signature::from_bytes(&sig_bytes);
        keys.verifying_key()
            .verify(att.binary_sha256.as_bytes(), &signature)
            .expect("node key must verify its own binary-hash signature");
        assert_eq!(att.signer_key_id, key_id_of(&keys.verifying_key()));

        // The crate's own verify helper agrees, and rejects a DIFFERENT key.
        assert!(att.verify_signature(&keys.verifying_key()));
        let other = KeyPair::generate();
        assert!(
            !att.verify_signature(&other.verifying_key()),
            "a different node key must NOT verify this binary-hash signature"
        );
    }

    /// Graceful degradation: an unresolvable/unreadable path yields NO
    /// attestation — never a fabricated hash or placeholder record.
    #[test]
    fn degrades_to_none_when_binary_unreadable() {
        let keys = KeyPair::generate();
        let missing = std::path::Path::new("/nonexistent/b3/serving-binary-xyz");
        assert!(
            measure_path(&keys, missing, "2026-08-30T00:00:00Z".to_string()).is_none(),
            "an unreadable binary path must record absence, never a fabricated attestation"
        );
    }
}
