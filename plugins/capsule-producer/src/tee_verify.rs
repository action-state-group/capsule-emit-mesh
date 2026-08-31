//! Local (network-free) verification for a parsed
//! [`crate::tee_attest::TdQuoteV4`].
//!
//! Two INDEPENDENT evidence-authenticity paths are provided, matching the
//! task's "PCS / Trust Authority" phrasing:
//!
//! - [`verify_dcap_quote`] — the quote's own ECDSA signature chain, verified
//!   locally against an operator-supplied Intel PCK/TDX root CA certificate
//!   ("PCS cert chain" path). No network call.
//! - [`verify_ita_token`] — an optional Intel Trust Authority attestation
//!   token (ES384 JWT) for the SAME quote, verified against an
//!   operator-supplied ITA public key ("Trust Authority" path). Also no
//!   network call — the node made that call when it submitted the quote to
//!   ITA (the HW-gated producer leg); this function only checks the token
//!   ITA already returned.
//!
//! Freshness/replay is a SEPARATE concern, handled by [`verify_binding`]
//! (REPORTDATA-vs-capsule/nonce), not by either path above.
//!
//! ## Trust anchors are NEVER hardcoded here
//!
//! This module does not bundle a pinned Intel root certificate or ITA public
//! key as a source constant. A wrong hardcoded root would be worse than no
//! root: it would make `verify_dcap_quote` either silently reject everything
//! real or — far worse — silently accept something it shouldn't, while
//! LOOKING verified. [`TrustedRoot::from_pem`] and [`verify_ita_token`]'s
//! `ita_verifying_key` parameter require the OPERATOR to supply these,
//! sourced from Intel's published PCS root CA certificate and Intel Trust
//! Authority's published signing key respectively. This is the same
//! "never fabricate" posture the rest of this crate takes toward evidence —
//! applied here to trust configuration instead of measurement data.
//!
//! ## Residual — read before trusting an `Ok(())` from this module
//!
//! Neither verification path here contacts Intel's live PCS or ITA service.
//! A quote/token can be structurally and cryptographically valid while the
//! platform's TCB is stale or the signing cert has since been revoked —
//! that requires a LIVE query against PCS TCB-info/QE-identity/CRL
//! collateral, or routing through ITA's live policy evaluation, which this
//! module does not perform. See `docs/REDTEAM-RUNG3.md` for this residual,
//! stated the same way `self_measured`'s ceiling is stated in-band.

use crate::tee_attest::{tee_binding_report_data, TdQuoteV4, QE_REPORT_LEN, REPORT_DATA_LEN};
use base64::Engine as _;
use der::{DecodePem, Encode};
use p256::ecdsa::{
    signature::Verifier as P256Verifier, Signature as P256Signature, VerifyingKey as P256VerifyingKey,
};
use p384::ecdsa::{Signature as P384Signature, VerifyingKey as P384VerifyingKey};
use sha2::{Digest, Sha256};
use x509_cert::Certificate;

/// `id-ecdsa-with-SHA256` (RFC 5480) — the only certificate/quote signature
/// algorithm this verifier accepts, matching what Intel's SGX/TDX PKI uses
/// throughout the PCK cert chain and the ECDSA-256-with-P-256 quote scheme.
const ECDSA_WITH_SHA256_OID: &str = "1.2.840.10045.4.3.2";

#[derive(Debug, thiserror::Error)]
pub enum TeeVerifyError {
    #[error("REPORTDATA does not match the expected binding for this capsule digest/nonce")]
    BindingMismatch,
    #[error("cert chain PEM did not parse: {0}")]
    CertChainParse(String),
    #[error("cert chain must have at least 2 certificates (leaf + at least one issuer)")]
    CertChainTooShort,
    #[error("certificate at chain position {0} uses an unsupported signature algorithm (expected ecdsa-with-SHA256)")]
    UnsupportedCertAlgorithm(usize),
    #[error("certificate signature invalid at chain position {0} (not signed by position {1}'s key)")]
    CertSignatureInvalid(usize, usize),
    #[error("cert chain's terminal certificate does not match the supplied trusted root")]
    UntrustedRoot,
    #[error("malformed EC public key or signature bytes: {0}")]
    MalformedEcData(&'static str),
    #[error("QE report signature invalid (not signed by the PCK leaf certificate's key)")]
    QeReportSignatureInvalid,
    #[error("attestation key is not bound to the QE report (SHA-256(attest_pub_key||qe_auth_data) mismatch)")]
    AttestationKeyNotBound,
    #[error("quote signature invalid (header||body not signed by the bound attestation key)")]
    QuoteSignatureInvalid,
    #[error("Trust Authority token malformed: {0}")]
    ItaTokenMalformed(&'static str),
    #[error("Trust Authority token signature invalid")]
    ItaTokenSignatureInvalid,
    #[error("Trust Authority token payload was not valid JSON: {0}")]
    ItaTokenPayloadInvalid(#[from] serde_json::Error),
}

/// Check that a quote's REPORTDATA is the binding this system expects for
/// ONE specific capsule exchange — the freshness/replay defense. Independent
/// of, and required alongside, either authenticity path below: a
/// cryptographically perfect quote for the WRONG exchange must still be
/// rejected.
pub fn verify_binding(
    quote: &TdQuoteV4,
    capsule_digest: &[u8],
    nonce: &[u8],
) -> Result<(), TeeVerifyError> {
    let expected = tee_binding_report_data(capsule_digest, nonce);
    // Constant-time compare: REPORTDATA is not secret, but there is no
    // reason to leak timing on a comparison this cheap to make constant.
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(quote.body.report_data.iter()) {
        diff |= a ^ b;
    }
    if diff == 0 {
        Ok(())
    } else {
        Err(TeeVerifyError::BindingMismatch)
    }
}

/// An operator-supplied trust anchor for the DCAP cert-chain path. Construct
/// from Intel's published SGX/TDX root CA certificate PEM — see module docs
/// for why this is never a bundled constant.
pub struct TrustedRoot {
    der: Vec<u8>,
}

impl TrustedRoot {
    pub fn from_pem(pem: &str) -> Result<Self, TeeVerifyError> {
        let cert = Certificate::from_pem(pem.as_bytes())
            .map_err(|e| TeeVerifyError::CertChainParse(e.to_string()))?;
        let der = cert
            .to_der()
            .map_err(|e| TeeVerifyError::CertChainParse(e.to_string()))?;
        Ok(TrustedRoot { der })
    }

    #[cfg(test)]
    fn from_certificate(cert: &Certificate) -> Self {
        TrustedRoot {
            der: cert.to_der().expect("test certificate encodes"),
        }
    }
}

fn p256_verifying_key_from_cert(cert: &Certificate) -> Result<P256VerifyingKey, TeeVerifyError> {
    let raw = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    P256VerifyingKey::from_sec1_bytes(raw).map_err(|_| {
        TeeVerifyError::MalformedEcData("certificate subjectPublicKeyInfo is not a valid P-256 point")
    })
}

/// Verify `child` was signed by `parent`'s public key. Both must use
/// `ecdsa-with-SHA256` (the only algorithm Intel's SGX/TDX PKI uses); any
/// other algorithm is rejected rather than silently skipped.
fn verify_cert_signed_by(
    child: &Certificate,
    child_index: usize,
    parent: &Certificate,
    parent_index: usize,
) -> Result<(), TeeVerifyError> {
    if child.signature_algorithm.oid.to_string() != ECDSA_WITH_SHA256_OID {
        return Err(TeeVerifyError::UnsupportedCertAlgorithm(child_index));
    }
    let tbs_der = child
        .tbs_certificate
        .to_der()
        .map_err(|e| TeeVerifyError::CertChainParse(e.to_string()))?;
    let sig_bytes = child.signature.raw_bytes();
    let signature = P256Signature::from_der(sig_bytes)
        .map_err(|_| TeeVerifyError::MalformedEcData("certificate signature is not valid DER ECDSA"))?;
    let parent_key = p256_verifying_key_from_cert(parent)?;
    parent_key
        .verify(&tbs_der, &signature)
        .map_err(|_| TeeVerifyError::CertSignatureInvalid(child_index, parent_index))
}

/// Verify the quote's DCAP evidence chain end-to-end, purely locally:
///
/// 1. The PCK cert chain in `cert_data` (leaf -> intermediate -> root)
///    chains by signature, and its terminal certificate matches
///    `trusted_root` exactly.
/// 2. The Quoting Enclave's own report (`qe_report`) is signed by the PCK
///    leaf certificate's key (`qe_report_sig`).
/// 3. The ephemeral attestation key is bound into that QE report
///    (`SHA-256(attest_pub_key || qe_auth_data)` matches the report's
///    trailing REPORTDATA field) — this is what stops a party who does NOT
///    hold a valid PCK cert from vouching for an arbitrary attestation key.
/// 4. The quote body itself (`header || body`, carrying MRTD/RTMR/REPORTDATA)
///    is signed by that same attestation key.
///
/// Does NOT check [`verify_binding`] (call separately) or TCB freshness/
/// revocation (see module docs' residual).
pub fn verify_dcap_quote(quote: &TdQuoteV4, trusted_root: &TrustedRoot) -> Result<(), TeeVerifyError> {
    let pem_chain = &quote.signature_data.cert_data.pem_chain;
    let certs = Certificate::load_pem_chain(pem_chain)
        .map_err(|e| TeeVerifyError::CertChainParse(e.to_string()))?;
    if certs.len() < 2 {
        return Err(TeeVerifyError::CertChainTooShort);
    }

    // (1) chain-of-signatures, leaf -> ... -> root.
    for i in 0..certs.len() - 1 {
        verify_cert_signed_by(&certs[i], i, &certs[i + 1], i + 1)?;
    }
    let terminal_der = certs
        .last()
        .expect("length checked above")
        .to_der()
        .map_err(|e| TeeVerifyError::CertChainParse(e.to_string()))?;
    if terminal_der != trusted_root.der {
        return Err(TeeVerifyError::UntrustedRoot);
    }

    // (2) QE report signed by the PCK leaf certificate.
    let leaf = &certs[0];
    let leaf_key = p256_verifying_key_from_cert(leaf)?;
    let qe_report_sig = P256Signature::try_from(quote.signature_data.qe_report_sig.as_slice())
        .map_err(|_| TeeVerifyError::MalformedEcData("qe_report_sig is not a valid raw ECDSA signature"))?;
    leaf_key
        .verify(&quote.signature_data.qe_report, &qe_report_sig)
        .map_err(|_| TeeVerifyError::QeReportSignatureInvalid)?;

    // (3) attestation key bound into that QE report's trailing report_data.
    let mut hasher = Sha256::new();
    hasher.update(quote.signature_data.attest_pub_key);
    hasher.update(&quote.signature_data.qe_auth_data);
    let digest = hasher.finalize();
    let mut expected_report_data = [0u8; REPORT_DATA_LEN];
    expected_report_data[..digest.len()].copy_from_slice(&digest);
    let actual_report_data = &quote.signature_data.qe_report[QE_REPORT_LEN - REPORT_DATA_LEN..];
    if actual_report_data != expected_report_data {
        return Err(TeeVerifyError::AttestationKeyNotBound);
    }

    // (4) quote body signed by the now-authenticated attestation key.
    let mut uncompressed = Vec::with_capacity(1 + quote.signature_data.attest_pub_key.len());
    uncompressed.push(0x04);
    uncompressed.extend_from_slice(&quote.signature_data.attest_pub_key);
    let attest_key = P256VerifyingKey::from_sec1_bytes(&uncompressed)
        .map_err(|_| TeeVerifyError::MalformedEcData("attest_pub_key is not a valid P-256 point"))?;
    let quote_sig = P256Signature::try_from(quote.signature_data.signature.as_slice())
        .map_err(|_| TeeVerifyError::MalformedEcData("quote signature is not a valid raw ECDSA signature"))?;
    attest_key
        .verify(quote.signed_bytes(), &quote_sig)
        .map_err(|_| TeeVerifyError::QuoteSignatureInvalid)?;

    Ok(())
}

fn base64url_decode(s: &str) -> Result<Vec<u8>, TeeVerifyError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| TeeVerifyError::ItaTokenMalformed("segment is not valid base64url"))
}

/// Verify an Intel Trust Authority attestation token (compact ES384 JWT) and
/// return its decoded claims. The token is evidence for the SAME quote via a
/// SEPARATE path from [`verify_dcap_quote`] — the node obtained it by
/// submitting the quote to ITA (that network call is the HW-gated producer
/// leg, not this function). `ita_verifying_key` is the operator-supplied ITA
/// signing key (see module docs).
pub fn verify_ita_token(
    token: &str,
    ita_verifying_key: &P384VerifyingKey,
) -> Result<serde_json::Value, TeeVerifyError> {
    let parts: Vec<&str> = token.split('.').collect();
    let [header_b64, payload_b64, sig_b64] = parts.as_slice() else {
        return Err(TeeVerifyError::ItaTokenMalformed(
            "expected exactly 3 dot-separated segments",
        ));
    };

    let header_bytes = base64url_decode(header_b64)?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)?;
    if header.get("alg").and_then(|v| v.as_str()) != Some("ES384") {
        return Err(TeeVerifyError::ItaTokenMalformed(
            "header \"alg\" must be \"ES384\"",
        ));
    }

    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig_bytes = base64url_decode(sig_b64)?;
    let signature = P384Signature::try_from(sig_bytes.as_slice())
        .map_err(|_| TeeVerifyError::MalformedEcData("ITA token signature is not a valid raw ES384 signature"))?;
    ita_verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| TeeVerifyError::ItaTokenSignatureInvalid)?;

    let payload_bytes = base64url_decode(payload_b64)?;
    let claims: serde_json::Value = serde_json::from_slice(&payload_bytes)?;
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tee_attest::tests::synthetic_quote;
    // `signature::Signer` is one trait shared by both curves' `Signer` type
    // aliases; importing it once (via the p256 path) is enough to call
    // `.sign()` on both a `p256::ecdsa::SigningKey` and a
    // `p384::ecdsa::SigningKey` below.
    use p256::ecdsa::signature::Signer as _;
    use p256::ecdsa::SigningKey as P256SigningKey;
    use p256::pkcs8::EncodePrivateKey as _;
    use p384::ecdsa::SigningKey as P384SigningKey;
    use rand_core::OsRng;
    use rcgen::{CertificateParams, KeyPair as RcgenKeyPair};
    use rustls_pki_types::PrivatePkcs8KeyDer;

    /// A synthetic PCK-style chain (root -> intermediate -> leaf), all
    /// ECDSA P-256, built at test time with `rcgen` — NOT Intel key
    /// material. Exercises the chain-of-signatures + trusted-root-match
    /// logic without depending on real Intel certificates. The `rcgen`
    /// key pairs and the `p256` signing keys are the SAME keys (rcgen's
    /// key is imported from the p256 key's PKCS8 DER encoding), so the
    /// test can sign raw quote bytes with `p256` while using `rcgen` only
    /// to produce well-formed X.509 certificates.
    struct SyntheticChain {
        pem_chain: Vec<u8>,
        trusted_root: TrustedRoot,
        leaf_signing_key: P256SigningKey,
    }

    fn matched_keypair() -> (P256SigningKey, RcgenKeyPair) {
        let signing_key = P256SigningKey::random(&mut OsRng);
        let pkcs8 = signing_key
            .to_pkcs8_der()
            .expect("p256 key encodes to PKCS8 DER");
        let pkcs8_der = PrivatePkcs8KeyDer::from(pkcs8.as_bytes());
        let rcgen_key =
            RcgenKeyPair::from_pkcs8_der_and_sign_algo(&pkcs8_der, &rcgen::PKCS_ECDSA_P256_SHA256)
                .expect("rcgen imports the same PKCS8 key");
        (signing_key, rcgen_key)
    }

    fn build_synthetic_chain() -> SyntheticChain {
        let (_root_signing_key, root_rcgen_key) = matched_keypair();
        let mut root_params = CertificateParams::new(vec!["Test Root CA".into()]).expect("root params");
        root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let root_cert = root_params.self_signed(&root_rcgen_key).expect("self-signed root");

        let (_inter_signing_key, inter_rcgen_key) = matched_keypair();
        let mut inter_params =
            CertificateParams::new(vec!["Test Intermediate CA".into()]).expect("intermediate params");
        inter_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let inter_cert = inter_params
            .signed_by(&inter_rcgen_key, &root_cert, &root_rcgen_key)
            .expect("intermediate signed by root");

        let (leaf_signing_key, leaf_rcgen_key) = matched_keypair();
        let leaf_params = CertificateParams::new(vec!["Test PCK Leaf".into()]).expect("leaf params");
        let leaf_cert = leaf_params
            .signed_by(&leaf_rcgen_key, &inter_cert, &inter_rcgen_key)
            .expect("leaf signed by intermediate");

        let mut pem_chain = Vec::new();
        pem_chain.extend_from_slice(leaf_cert.pem().as_bytes());
        pem_chain.extend_from_slice(inter_cert.pem().as_bytes());
        pem_chain.extend_from_slice(root_cert.pem().as_bytes());

        let root_x509 =
            Certificate::from_pem(root_cert.pem().as_bytes()).expect("root parses as x509_cert");

        SyntheticChain {
            pem_chain,
            trusted_root: TrustedRoot::from_certificate(&root_x509),
            leaf_signing_key,
        }
    }

    #[test]
    fn binding_matches_expected_and_rejects_mismatch() {
        let report_data = tee_binding_report_data(b"capsule-digest", b"nonce");
        let (bytes, _, _) = synthetic_quote(report_data, b"x");
        let quote = TdQuoteV4::parse(&bytes).unwrap();
        assert!(verify_binding(&quote, b"capsule-digest", b"nonce").is_ok());
        assert!(matches!(
            verify_binding(&quote, b"different-digest", b"nonce"),
            Err(TeeVerifyError::BindingMismatch)
        ));
        assert!(matches!(
            verify_binding(&quote, b"capsule-digest", b"different-nonce"),
            Err(TeeVerifyError::BindingMismatch)
        ));
    }

    /// Hand-build a quote whose signature section is REAL (signed by real
    /// `p256` keys tied to the synthetic PCK chain), unlike
    /// `tee_attest::tests::synthetic_quote`'s placeholder `0x11`/`0x22`/...
    /// bytes — this is what exercises `verify_dcap_quote`'s cryptography.
    fn build_signed_quote(chain: &SyntheticChain, report_data: [u8; REPORT_DATA_LEN]) -> Vec<u8> {
        let attest_signing_key = P256SigningKey::random(&mut OsRng);
        let attest_pub_point = attest_signing_key.verifying_key().to_encoded_point(false);
        let attest_pub_bytes: [u8; 64] = attest_pub_point.as_bytes()[1..]
            .try_into()
            .expect("uncompressed P-256 point is 65 bytes (0x04 + 64)");

        let qe_auth_data: Vec<u8> = vec![];
        let mut hasher = Sha256::new();
        hasher.update(attest_pub_bytes);
        hasher.update(&qe_auth_data);
        let digest = hasher.finalize();
        let mut qe_report = [0u8; QE_REPORT_LEN];
        qe_report[QE_REPORT_LEN - REPORT_DATA_LEN..QE_REPORT_LEN - REPORT_DATA_LEN + digest.len()]
            .copy_from_slice(&digest);
        let qe_report_sig: P256Signature = chain.leaf_signing_key.sign(&qe_report);

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
        header_and_body.extend_from_slice(&[7u8; 48]); // mrtd
        header_and_body.extend_from_slice(&[0u8; 48]);
        header_and_body.extend_from_slice(&[0u8; 48]);
        header_and_body.extend_from_slice(&[0u8; 48]);
        for r in 0..4u8 {
            header_and_body.extend_from_slice(&[r; 48]); // rtmr0..3
        }
        header_and_body.extend_from_slice(&report_data);

        let quote_sig: P256Signature = attest_signing_key.sign(&header_and_body);

        let mut section = Vec::new();
        section.extend_from_slice(quote_sig.to_bytes().as_slice());
        section.extend_from_slice(&attest_pub_bytes);
        section.extend_from_slice(&qe_report);
        section.extend_from_slice(qe_report_sig.to_bytes().as_slice());
        section.extend_from_slice(&(qe_auth_data.len() as u16).to_le_bytes());
        section.extend_from_slice(&qe_auth_data);
        section.extend_from_slice(&5u16.to_le_bytes());
        section.extend_from_slice(&(chain.pem_chain.len() as u32).to_le_bytes());
        section.extend_from_slice(&chain.pem_chain);

        let mut out = header_and_body;
        out.extend_from_slice(&(section.len() as u32).to_le_bytes());
        out.extend_from_slice(&section);
        out
    }

    #[test]
    fn dcap_chain_verifies_end_to_end_against_synthetic_pck_chain() {
        let chain = build_synthetic_chain();
        let report_data = tee_binding_report_data(b"capsule-digest", b"nonce");
        let bytes = build_signed_quote(&chain, report_data);

        let quote = TdQuoteV4::parse(&bytes).expect("hand-built quote parses");
        assert!(verify_binding(&quote, b"capsule-digest", b"nonce").is_ok());
        verify_dcap_quote(&quote, &chain.trusted_root).expect("full DCAP chain must verify");
    }

    #[test]
    fn dcap_chain_rejects_wrong_trusted_root() {
        let chain = build_synthetic_chain();
        let (_other_signing_key, other_root_rcgen_key) = matched_keypair();
        let mut other_params = CertificateParams::new(vec!["Other Root".into()]).unwrap();
        other_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let other_root_cert = other_params.self_signed(&other_root_rcgen_key).unwrap();
        let other_root_x509 = Certificate::from_pem(other_root_cert.pem().as_bytes()).unwrap();
        let wrong_root = TrustedRoot::from_certificate(&other_root_x509);

        let report_data = tee_binding_report_data(b"capsule-digest", b"nonce");
        let bytes = build_signed_quote(&chain, report_data);
        let quote = TdQuoteV4::parse(&bytes).unwrap();
        assert!(matches!(
            verify_dcap_quote(&quote, &wrong_root),
            Err(TeeVerifyError::UntrustedRoot)
        ));
    }

    #[test]
    fn dcap_chain_rejects_tampered_qe_report_signature() {
        let chain = build_synthetic_chain();
        let report_data = tee_binding_report_data(b"capsule-digest", b"nonce");
        let mut bytes = build_signed_quote(&chain, report_data);
        // Flip a byte inside the qe_report_sig field (right after
        // signature[64] + attest_pub_key[64] + qe_report[384] in the
        // signature section, which starts after header[48]+body[584]+len[4]).
        let qe_report_sig_offset = crate::tee_attest::HEADER_LEN
            + crate::tee_attest::BODY_LEN
            + 4
            + crate::tee_attest::EC_SIG_LEN
            + crate::tee_attest::EC_PUBKEY_LEN
            + crate::tee_attest::QE_REPORT_LEN;
        bytes[qe_report_sig_offset] ^= 0xFF;
        let quote = TdQuoteV4::parse(&bytes).unwrap();
        assert!(matches!(
            verify_dcap_quote(&quote, &chain.trusted_root),
            Err(TeeVerifyError::QeReportSignatureInvalid)
        ));
    }

    #[test]
    fn ita_token_verifies_valid_and_rejects_tampered() {
        let signing_key = P384SigningKey::random(&mut OsRng);
        let verifying_key = *signing_key.verifying_key();

        let header =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"ES384","typ":"JWT"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"tdx_mrtd":"deadbeef","verifier":"trust-authority"}"#);
        let signing_input = format!("{header}.{payload}");

        let sig: P384Signature = signing_key.sign(signing_input.as_bytes());
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes().as_slice());
        let token = format!("{signing_input}.{sig_b64}");

        let claims = verify_ita_token(&token, &verifying_key).expect("valid token verifies");
        assert_eq!(claims["tdx_mrtd"], "deadbeef");

        // Tamper with the payload only, keep the original signature.
        let tampered_payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"tdx_mrtd":"00000000","verifier":"trust-authority"}"#);
        let tampered = format!("{header}.{tampered_payload}.{sig_b64}");
        assert!(matches!(
            verify_ita_token(&tampered, &verifying_key),
            Err(TeeVerifyError::ItaTokenSignatureInvalid)
        ));

        // Wrong verifying key must also fail.
        let other_key = *P384SigningKey::random(&mut OsRng).verifying_key();
        assert!(matches!(
            verify_ita_token(&token, &other_key),
            Err(TeeVerifyError::ItaTokenSignatureInvalid)
        ));
    }

    #[test]
    fn ita_token_rejects_malformed_shape_and_wrong_alg() {
        let key = *P384SigningKey::random(&mut OsRng).verifying_key();
        assert!(matches!(
            verify_ita_token("not-a-jwt", &key),
            Err(TeeVerifyError::ItaTokenMalformed(_))
        ));

        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{}"#);
        let token = format!("{header}.{payload}.deadbeef");
        assert!(matches!(
            verify_ita_token(&token, &key),
            Err(TeeVerifyError::ItaTokenMalformed(_))
        ));
    }
}
