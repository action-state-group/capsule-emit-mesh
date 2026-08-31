// SPDX-License-Identifier: Apache-2.0
//! Rung 3c — adversarial red-team of the `tee_measured` rung
//! (`capsule_producer::tee_attest` + `capsule_producer::tee_verify`).
//!
//! **What rung 3c is.** The strongest measurement grade this codebase names:
//! MRTD/RTMR[0..3] are measured and signed by the TDX module BENEATH the
//! guest OS, not by the serving process. This is the rung that is supposed to
//! close RUNG2 attack 8 (`docs/REDTEAM-RUNG2.md`) — a root-compromised host
//! signing a decoy hash under the `self_measured` label. This file turns that
//! claim into executable evidence, the same way
//! `redteam_rung2_self_measured.rs` did for B3.
//!
//! **Method.** Each attack builds a REAL synthetic PCK-style cert chain and
//! signs a REAL quote with `p256`/`p384` keys tied to it (not placeholder
//! bytes) — the same construction `tee_verify`'s own unit tests use — then
//! tampers with exactly one thing and checks the outcome against
//! `capsule_producer::tee_verify`. Outcome vocabulary matches the other
//! red-team docs:
//!   CAUGHT   — rejected.
//!   LABELED  — accepted but the gap is named honestly (a verifier can see it).
//!   RESIDUAL — succeeds; the rung has no handle. Closing rung named inline.
//!
//! Run: `cargo test --manifest-path plugins/capsule-producer/Cargo.toml --test redteam_rung3_tee_measured`

use base64::Engine as _;
use capsule_producer::tee_attest::{
    tee_binding_report_data, TdQuoteV4, BODY_LEN, EC_PUBKEY_LEN, EC_SIG_LEN, HEADER_LEN,
    QE_REPORT_LEN, REPORT_DATA_LEN,
};
use capsule_producer::tee_verify::{verify_binding, verify_dcap_quote, verify_ita_token, TrustedRoot, TeeVerifyError};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use p256::pkcs8::EncodePrivateKey as _;
use p384::ecdsa::{Signature as P384Signature, SigningKey as P384SigningKey};
use rand_core::OsRng;
use rustls_pki_types::PrivatePkcs8KeyDer;
use sha2::{Digest, Sha256};

/// A synthetic PCK-style chain (root -> intermediate -> leaf), all ECDSA
/// P-256, built at test time — NOT real Intel key material. The `rcgen`
/// certs and the `p256` signing keys used for raw quote signing are the SAME
/// keys (imported from the same PKCS8 DER), so signatures made with the raw
/// `p256` API verify against the certs.
struct SyntheticChain {
    pem_chain: Vec<u8>,
    trusted_root: TrustedRoot,
    leaf_signing_key: P256SigningKey,
}

fn matched_keypair() -> (P256SigningKey, rcgen::KeyPair) {
    let signing_key = P256SigningKey::random(&mut OsRng);
    let pkcs8 = signing_key.to_pkcs8_der().expect("p256 key encodes to PKCS8 DER");
    let pkcs8_der = PrivatePkcs8KeyDer::from(pkcs8.as_bytes());
    let rcgen_key = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8_der, &rcgen::PKCS_ECDSA_P256_SHA256)
        .expect("rcgen imports the same PKCS8 key");
    (signing_key, rcgen_key)
}

fn build_synthetic_chain() -> SyntheticChain {
    let (_root_key, root_rcgen) = matched_keypair();
    let mut root_params = rcgen::CertificateParams::new(vec!["Test Root CA".into()]).unwrap();
    root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let root_cert = root_params.self_signed(&root_rcgen).unwrap();

    let (_inter_key, inter_rcgen) = matched_keypair();
    let mut inter_params = rcgen::CertificateParams::new(vec!["Test Intermediate CA".into()]).unwrap();
    inter_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let inter_cert = inter_params.signed_by(&inter_rcgen, &root_cert, &root_rcgen).unwrap();

    let (leaf_signing_key, leaf_rcgen) = matched_keypair();
    let leaf_params = rcgen::CertificateParams::new(vec!["Test PCK Leaf".into()]).unwrap();
    let leaf_cert = leaf_params.signed_by(&leaf_rcgen, &inter_cert, &inter_rcgen).unwrap();

    let mut pem_chain = Vec::new();
    pem_chain.extend_from_slice(leaf_cert.pem().as_bytes());
    pem_chain.extend_from_slice(inter_cert.pem().as_bytes());
    pem_chain.extend_from_slice(root_cert.pem().as_bytes());

    SyntheticChain {
        pem_chain,
        trusted_root: TrustedRoot::from_pem(&root_cert.pem()).unwrap(),
        leaf_signing_key,
    }
}

/// Options for [`build_quote`] so each attack can tamper with exactly one
/// input.
struct QuoteOptions<'a> {
    mrtd: [u8; 48],
    rtmr0: [u8; 48],
    report_data: [u8; REPORT_DATA_LEN],
    chain: &'a SyntheticChain,
    /// When `true`, the attestation key embedded in the quote is a
    /// DIFFERENT key than the one whose SHA-256 is bound into `qe_report`'s
    /// trailing field (simulates presenting an unauthorized attestation key).
    unbound_attestation_key: bool,
    /// When `Some`, flip this byte offset in the fully-assembled quote AFTER
    /// all signatures are computed (simulates a post-signing tamper).
    tamper_byte_after_signing: Option<usize>,
}

fn build_quote(opts: QuoteOptions<'_>) -> Vec<u8> {
    let attest_signing_key = P256SigningKey::random(&mut OsRng);
    let attest_pub_point = attest_signing_key.verifying_key().to_encoded_point(false);
    let attest_pub_bytes: [u8; EC_PUBKEY_LEN] =
        attest_pub_point.as_bytes()[1..].try_into().expect("64-byte raw point");

    // The key whose hash gets bound into qe_report — normally the SAME as
    // the attestation key. `unbound_attestation_key` breaks that on purpose.
    let bound_pub_bytes: [u8; EC_PUBKEY_LEN] = if opts.unbound_attestation_key {
        let decoy = P256SigningKey::random(&mut OsRng);
        let decoy_point = decoy.verifying_key().to_encoded_point(false);
        decoy_point.as_bytes()[1..].try_into().unwrap()
    } else {
        attest_pub_bytes
    };

    let qe_auth_data: Vec<u8> = vec![];
    let mut hasher = Sha256::new();
    hasher.update(bound_pub_bytes);
    hasher.update(&qe_auth_data);
    let digest = hasher.finalize();
    let mut qe_report = [0u8; QE_REPORT_LEN];
    qe_report[QE_REPORT_LEN - REPORT_DATA_LEN..QE_REPORT_LEN - REPORT_DATA_LEN + digest.len()]
        .copy_from_slice(&digest);
    let qe_report_sig: P256Signature = opts.chain.leaf_signing_key.sign(&qe_report);

    let mut header_and_body = Vec::new();
    header_and_body.extend_from_slice(&4u16.to_le_bytes());
    header_and_body.extend_from_slice(&2u16.to_le_bytes());
    header_and_body.extend_from_slice(&0x0000_0081u32.to_le_bytes());
    header_and_body.extend_from_slice(&[0u8; 4]);
    header_and_body.extend_from_slice(&[0xAB; 16]);
    header_and_body.extend_from_slice(&[0xCD; 20]);
    header_and_body.extend_from_slice(&[0u8; 16]);
    header_and_body.extend_from_slice(&[0u8; 48]);
    header_and_body.extend_from_slice(&[0u8; 48]);
    header_and_body.extend_from_slice(&0u64.to_le_bytes());
    header_and_body.extend_from_slice(&0u64.to_le_bytes());
    header_and_body.extend_from_slice(&0u64.to_le_bytes());
    header_and_body.extend_from_slice(&opts.mrtd);
    header_and_body.extend_from_slice(&[0u8; 48]);
    header_and_body.extend_from_slice(&[0u8; 48]);
    header_and_body.extend_from_slice(&[0u8; 48]);
    header_and_body.extend_from_slice(&opts.rtmr0);
    header_and_body.extend_from_slice(&[0u8; 48]);
    header_and_body.extend_from_slice(&[0u8; 48]);
    header_and_body.extend_from_slice(&[0u8; 48]);
    header_and_body.extend_from_slice(&opts.report_data);
    assert_eq!(header_and_body.len(), HEADER_LEN + BODY_LEN);

    let quote_sig: P256Signature = attest_signing_key.sign(&header_and_body);

    let mut section = Vec::new();
    section.extend_from_slice(quote_sig.to_bytes().as_slice());
    section.extend_from_slice(&attest_pub_bytes);
    section.extend_from_slice(&qe_report);
    section.extend_from_slice(qe_report_sig.to_bytes().as_slice());
    section.extend_from_slice(&(qe_auth_data.len() as u16).to_le_bytes());
    section.extend_from_slice(&qe_auth_data);
    section.extend_from_slice(&5u16.to_le_bytes());
    section.extend_from_slice(&(opts.chain.pem_chain.len() as u32).to_le_bytes());
    section.extend_from_slice(&opts.chain.pem_chain);

    let mut out = header_and_body;
    out.extend_from_slice(&(section.len() as u32).to_le_bytes());
    out.extend_from_slice(&section);

    if let Some(offset) = opts.tamper_byte_after_signing {
        out[offset] ^= 0xFF;
    }
    out
}

fn default_opts(chain: &SyntheticChain, report_data: [u8; REPORT_DATA_LEN]) -> QuoteOptions<'_> {
    QuoteOptions {
        mrtd: [7u8; 48],
        rtmr0: [1u8; 48],
        report_data,
        chain,
        unbound_attestation_key: false,
        tamper_byte_after_signing: None,
    }
}

/// ATTACK 11 — QUOTE REPLAY ACROSS A DIFFERENT CAPSULE.
///
/// A genuinely valid, hardware-signed quote for exchange A is presented as
/// evidence for a DIFFERENT exchange B (same node, different capsule digest).
/// -> CAUGHT. `verify_binding` recomputes REPORTDATA from B's own capsule
/// digest/nonce; a quote minted for A's digest cannot match.
#[test]
fn attack11_quote_replayed_across_a_different_capsule_is_caught_by_binding() {
    let chain = build_synthetic_chain();
    let report_data_for_a = tee_binding_report_data(b"capsule-A-digest", b"nonce-1");
    let bytes = build_quote(default_opts(&chain, report_data_for_a));
    let quote = TdQuoteV4::parse(&bytes).unwrap();

    assert!(verify_binding(&quote, b"capsule-A-digest", b"nonce-1").is_ok());
    assert!(matches!(
        verify_binding(&quote, b"capsule-B-digest", b"nonce-1"),
        Err(TeeVerifyError::BindingMismatch)
    ));
}

/// ATTACK 12 — QUOTE REPLAY WITH A STALE NONCE.
///
/// Same exchange digest, but the requester's nonce rotated (a fresh request
/// for the same logical exchange). -> CAUGHT for the same reason as attack 11
/// — REPORTDATA binds nonce too, not just the digest.
#[test]
fn attack12_quote_replayed_with_a_stale_nonce_is_caught_by_binding() {
    let chain = build_synthetic_chain();
    let report_data = tee_binding_report_data(b"capsule-digest", b"nonce-old");
    let bytes = build_quote(default_opts(&chain, report_data));
    let quote = TdQuoteV4::parse(&bytes).unwrap();

    assert!(matches!(
        verify_binding(&quote, b"capsule-digest", b"nonce-new"),
        Err(TeeVerifyError::BindingMismatch)
    ));
}

/// ATTACK 13 — CERT CHAIN ROOTED AT AN ATTACKER-CONTROLLED CA.
///
/// The node runs its OWN CA, issues itself a "PCK-shaped" cert chain, and
/// signs a quote with it — structurally identical to a real DCAP quote.
/// -> CAUGHT. `verify_dcap_quote` requires the chain's terminal certificate
/// to match the OPERATOR-SUPPLIED trusted root exactly; an attacker-issued
/// root never matches Intel's.
#[test]
fn attack13_cert_chain_rooted_at_attacker_controlled_ca_is_caught() {
    let attacker_chain = build_synthetic_chain();
    let real_intel_root = build_synthetic_chain(); // stands in for "the real Intel root"

    let report_data = tee_binding_report_data(b"capsule-digest", b"nonce");
    let bytes = build_quote(default_opts(&attacker_chain, report_data));
    let quote = TdQuoteV4::parse(&bytes).unwrap();

    assert!(matches!(
        verify_dcap_quote(&quote, &real_intel_root.trusted_root),
        Err(TeeVerifyError::UntrustedRoot)
    ));
}

/// ATTACK 14 — FORGED QE REPORT SIGNATURE (no valid PCK cert held).
///
/// An attacker without ANY valid PCK certificate tries to vouch for an
/// attestation key by self-signing the QE report with a key that is not the
/// leaf certificate's key. -> CAUGHT. `verify_dcap_quote` checks
/// `qe_report_sig` against the PCK LEAF certificate's own key specifically.
#[test]
fn attack14_forged_qe_report_signature_without_a_valid_pck_cert_is_caught() {
    let chain = build_synthetic_chain();
    let report_data = tee_binding_report_data(b"capsule-digest", b"nonce");
    let mut bytes = build_quote(default_opts(&chain, report_data));

    // Flip a byte inside qe_report_sig (right after
    // signature[64]+attest_pub_key[64]+qe_report[384], past header+body+len).
    let qe_report_sig_offset =
        HEADER_LEN + BODY_LEN + 4 + EC_SIG_LEN + EC_PUBKEY_LEN + QE_REPORT_LEN;
    bytes[qe_report_sig_offset] ^= 0xFF;

    let quote = TdQuoteV4::parse(&bytes).unwrap();
    assert!(matches!(
        verify_dcap_quote(&quote, &chain.trusted_root),
        Err(TeeVerifyError::QeReportSignatureInvalid)
    ));
}

/// ATTACK 15 — ATTESTATION KEY NOT BOUND INTO THE VOUCHED-FOR QE REPORT.
///
/// The PCK leaf legitimately signs a QE report — but for a DIFFERENT
/// attestation key than the one that actually signs this quote (key
/// substitution after the PCK vouch). -> CAUGHT. The QE report's trailing
/// field must equal `SHA-256(attest_pub_key||qe_auth_data)` for the key
/// PRESENT in the quote; substituting the key breaks that binding even
/// though `qe_report_sig` itself is a genuine PCK signature.
#[test]
fn attack15_attestation_key_not_bound_into_qe_report_is_caught() {
    let chain = build_synthetic_chain();
    let report_data = tee_binding_report_data(b"capsule-digest", b"nonce");
    let mut opts = default_opts(&chain, report_data);
    opts.unbound_attestation_key = true;
    let bytes = build_quote(opts);
    let quote = TdQuoteV4::parse(&bytes).unwrap();

    assert!(matches!(
        verify_dcap_quote(&quote, &chain.trusted_root),
        Err(TeeVerifyError::AttestationKeyNotBound)
    ));
}

/// ATTACK 16 (THE HEADLINE) — POST-SIGNING MEASUREMENT TAMPER.
///
/// This is the attack RUNG2 attack 8 (`docs/REDTEAM-RUNG2.md`) showed
/// SUCCEEDING against `self_measured`: a root-compromised host swaps in a
/// pristine/decoy measurement and signs THAT. Here the analogous move is
/// tried against `tee_measured` — flip a single byte of MRTD after the
/// quote was signed (simulating a host that tries to present a measurement
/// the TDX module never actually produced).
///
/// -> CAUGHT, unlike rung 2's residual. There is no code path in the guest
/// that can make the CPU sign an MRTD/RTMR it did not measure; any
/// post-signing edit to `header||body` invalidates `quote_sig` because the
/// attestation key signed the ORIGINAL bytes. This is the concrete evidence
/// for the module docs' claim: "a root-compromised host cannot forge this
/// the way it can forge a self_measured attestation."
#[test]
fn attack16_headline_post_signing_measurement_tamper_is_caught_where_self_measured_was_not() {
    let chain = build_synthetic_chain();
    let report_data = tee_binding_report_data(b"capsule-digest", b"nonce");
    let mut opts = default_opts(&chain, report_data);
    // Byte 0 of the body's mrtd field, i.e. offset HEADER_LEN + (16+48+48+8+8+8).
    let mrtd_offset = HEADER_LEN + 16 + 48 + 48 + 8 + 8 + 8;
    opts.tamper_byte_after_signing = Some(mrtd_offset);
    let bytes = build_quote(opts);
    let quote = TdQuoteV4::parse(&bytes).unwrap();

    assert!(matches!(
        verify_dcap_quote(&quote, &chain.trusted_root),
        Err(TeeVerifyError::QuoteSignatureInvalid)
    ));
}

/// RESIDUAL 1 — TCB FRESHNESS / REVOCATION IS NOT CHECKED OFFLINE.
///
/// A quote from a platform whose TCB is stale, or whose PCK cert has since
/// been revoked, is STILL structurally and cryptographically perfect: the
/// signature chain and REPORTDATA binding this module checks are unaffected
/// by TCB/revocation state. -> RESIDUAL (labeled, not caught). A live query
/// against Intel PCS TCB-info/QE-identity/CRL collateral, or routing through
/// Trust Authority's policy evaluation, is required to close this — this
/// offline verifier deliberately does not perform it (see `tee_verify`
/// module docs).
#[test]
fn residual1_offline_verifier_cannot_see_tcb_staleness_or_revocation() {
    let chain = build_synthetic_chain();
    let report_data = tee_binding_report_data(b"capsule-digest", b"nonce");
    // `tee_tcb_svn` (the field that would carry a stale/revoked TCB security
    // version in a real quote) is zeroed by `build_quote` regardless of
    // input -- there is no verifier-side check on it at all, which is
    // exactly the point of this test: an all-zero (== "ancient"/unpatched)
    // TCB SVN passes just as cleanly as any other.
    let bytes = build_quote(default_opts(&chain, report_data));
    let quote = TdQuoteV4::parse(&bytes).unwrap();

    verify_dcap_quote(&quote, &chain.trusted_root)
        .expect("structurally/cryptographically valid quote verifies regardless of TCB SVN");
}

/// RESIDUAL 2 — ITA TOKEN VERIFICATION CHECKS SIGNATURE SHAPE, NOT CLAIM
/// FRESHNESS.
///
/// `verify_ita_token` proves the token was signed by the holder of
/// `ita_verifying_key` and decodes its claims -- it does NOT evaluate
/// whether those claims assert a fresh/passing verdict. A validly-signed
/// token asserting a stale or adversarial-looking verdict still verifies.
/// -> RESIDUAL (labeled): the CALLER must inspect the decoded claims (e.g.
/// a policy/expiry field ITA includes) to close this; `verify_ita_token`'s
/// contract is authenticity of the token, not truth of its content.
#[test]
fn residual2_ita_token_verifies_signature_shape_only_not_claim_freshness() {
    let signing_key = P384SigningKey::random(&mut OsRng);
    let verifying_key = *signing_key.verifying_key();

    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"ES384","typ":"JWT"}"#);
    // A deliberately stale-looking claim -- still a well-formed, honestly
    // signed token from ITA's perspective.
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(br#"{"tdx_mrtd":"deadbeef","verified_at":"2020-01-01T00:00:00Z","verdict":"pass"}"#);
    let signing_input = format!("{header}.{payload}");
    let sig: P384Signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes().as_slice());
    let token = format!("{signing_input}.{sig_b64}");

    let claims = verify_ita_token(&token, &verifying_key).expect("authentic signature still verifies");
    assert_eq!(claims["verified_at"], "2020-01-01T00:00:00Z");
    // The function returned Ok despite the obviously-stale claim -- proving
    // freshness is the CALLER's job, not this function's.
}
