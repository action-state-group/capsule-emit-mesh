//! `tee_measured` rung (task B-rung3c): the record shape and structural
//! parser for an Intel TDX attestation quote, carrying a caller-bound
//! REPORTDATA field so a verifier can tie the quote to ONE specific capsule
//! exchange rather than any quote the TD ever produced.
//!
//! ## HONESTY GRADE — read this before trusting the rung
//!
//! `tee_measured` is the strongest grade this codebase names (see
//! [`crate::runtime_attest::MeasurementClass`]): the measurement (`MRTD` +
//! `RTMR[0..3]`) is produced and signed by the TDX module/CPU **beneath** the
//! guest OS and the serving process, not by the process itself. A
//! root-compromised host cannot forge it the way it can forge a
//! [`crate::runtime_attest::MeasurementClass::SelfMeasured`] attestation
//! (see `docs/REDTEAM-RUNG2.md` attack 8) — there is no code path in the
//! guest that can make the CPU sign an MRTD/RTMR it did not itself measure.
//!
//! What it does NOT prove: that Intel's DCAP PKI is uncompromised, that the
//! platform's TCB is up to date (no revoked/out-of-date microcode), or that a
//! quote presented to a verifier is FRESH rather than replayed. Freshness and
//! target-binding are handled by [`tee_binding_report_data`] below; TCB
//! recency/revocation require a LIVE query against Intel's PCS collateral
//! (TCB info, QE identity, CRL) or Intel Trust Authority, which this module
//! does not perform — see `docs/REDTEAM-RUNG3.md` for the residual, stated
//! the same way `self_measured`'s ceiling is stated in-band, not concealed.
//!
//! ## Scope of this module (rung 3c)
//!
//! This module defines the record shape and the HARDWARE-INDEPENDENT quote
//! parser only. It does not read `/sys/kernel/config/tsm/report/` or any
//! other live TDX interface — obtaining a REAL quote on the provisioned node
//! is the separate, HW-gated producer leg. A quote is always caller-supplied
//! bytes here (from a live TD, or a synthetic quote in tests); this module
//! never fabricates one. Cryptographic verification of a parsed quote (cert
//! chain, signatures, optional Intel Trust Authority token) lives in
//! [`crate::tee_verify`].

use crate::runtime_attest::MeasurementClass;
use serde_json::{json, Value};
use sha2::{Digest, Sha512};

/// Domain tag mixed into [`tee_binding_report_data`] so a TDX REPORTDATA
/// value bound by this system can never collide with REPORTDATA computed by
/// an unrelated binding scheme (same convention as the domain-tagged
/// canonical claims elsewhere in this codebase, e.g. B4 owner-binding).
pub const TEE_BINDING_DOMAIN_TAG: &[u8] = b"capsule-emit-mesh/tee-binding/v1";

/// Byte lengths of the TD Quote v4 fields this module parses. Named so the
/// parser and its tests share one source of truth instead of repeating magic
/// numbers.
pub const HEADER_LEN: usize = 48;
pub const BODY_LEN: usize = 584;
pub const MRTD_LEN: usize = 48;
pub const RTMR_LEN: usize = 48;
pub const RTMR_COUNT: usize = 4;
pub const REPORT_DATA_LEN: usize = 64;
pub const EC_SIG_LEN: usize = 64;
pub const EC_PUBKEY_LEN: usize = 64;
pub const QE_REPORT_LEN: usize = 384;

/// Compute the 64-byte REPORTDATA a TDX quote must carry to be accepted as
/// bound to ONE specific capsule exchange: `SHA-512(domain_tag ||
/// capsule_digest || nonce)`. SHA-512's 64-byte output fills the field
/// exactly, no truncation or padding.
///
/// `capsule_digest` is the exchange's content-address (the same digest bytes
/// the capsule's own `capsule_id`/exchange digest is built from);
/// `nonce` is the freshness value the requester/mesh already carries
/// (`client_nonce`). Binding both means a captured quote cannot be replayed
/// against a different exchange (wrong digest) or an old exchange (wrong
/// nonce) without the mismatch being visible to a verifier.
pub fn tee_binding_report_data(capsule_digest: &[u8], nonce: &[u8]) -> [u8; REPORT_DATA_LEN] {
    let mut hasher = Sha512::new();
    hasher.update(TEE_BINDING_DOMAIN_TAG);
    hasher.update(capsule_digest);
    hasher.update(nonce);
    hasher.finalize().into()
}

#[derive(Debug, thiserror::Error)]
pub enum TeeQuoteError {
    #[error("quote too short: need at least {need} bytes, got {got}")]
    TooShort { need: usize, got: usize },
    #[error("unsupported quote version {0} (only TDX DCAP v4 is parsed)")]
    UnsupportedVersion(u16),
    #[error("unsupported TEE type 0x{0:08x} (only TDX 0x00000081 is parsed)")]
    UnsupportedTeeType(u32),
    #[error("truncated signature/cert data: {0}")]
    TruncatedSignatureData(&'static str),
    #[error("unsupported certification data type {0} (only type 5, PCK cert chain, is parsed)")]
    UnsupportedCertDataType(u16),
    #[error("certification data is not valid UTF-8 PEM: {0}")]
    CertDataNotUtf8(#[from] std::str::Utf8Error),
}

/// TD Quote v4 header (`sizeof == `[`HEADER_LEN`]`` bytes, Intel TDX DCAP
/// Quote Generation Library layout).
#[derive(Clone, Debug)]
pub struct TdQuoteHeader {
    pub version: u16,
    /// `2` == ECDSA-256-with-P-256-curve, the only attestation key type TDX
    /// DCAP quotes use today.
    pub attestation_key_type: u16,
    /// `0x0000_0081` for TDX (vs `0x0000_0000` for plain SGX).
    pub tee_type: u32,
    pub qe_vendor_id: [u8; 16],
    pub user_data: [u8; 20],
}

/// TD Quote Body (`sizeof == `[`BODY_LEN`]`` bytes): the measurement
/// registers signed by the TDX module, plus the caller-bound `report_data`.
#[derive(Clone, Debug)]
pub struct TdQuoteBody {
    pub tee_tcb_svn: [u8; 16],
    pub mrseam: [u8; 48],
    pub mrsignerseam: [u8; 48],
    pub seam_attributes: u64,
    pub td_attributes: u64,
    pub xfam: u64,
    /// Measurement of the TD's initial contents (build-time measurement).
    pub mrtd: [u8; MRTD_LEN],
    pub mrconfigid: [u8; 48],
    pub mrowner: [u8; 48],
    pub mrownerconfig: [u8; 48],
    /// Runtime measurement registers 0-3, extended after boot (RTMR0..3).
    pub rtmr: [[u8; RTMR_LEN]; RTMR_COUNT],
    /// Caller-bound field; this system fills it with
    /// [`tee_binding_report_data`]'s output.
    pub report_data: [u8; REPORT_DATA_LEN],
}

/// The QE's own SGX certification data (Certification Data Type 5 = a
/// concatenated PEM PCK certificate chain: leaf, intermediate CA, root CA, in
/// that order — Intel's documented DCAP quote cert-data encoding).
#[derive(Clone, Debug)]
pub struct QeCertData {
    pub cert_data_type: u16,
    /// Raw concatenated PEM bytes exactly as carried in the quote. Splitting
    /// into individual certificates is [`crate::tee_verify`]'s job (it needs
    /// the parsed `x509_cert::Certificate`s, which this HW-independent
    /// structural module does not depend on).
    pub pem_chain: Vec<u8>,
}

/// The ECDSA quote signature section (Intel `sgx_ql_ecdsa_sig_data_t` layout,
/// reused verbatim by TDX quotes since the Quoting Enclave that signs the
/// attestation key is still an SGX enclave).
#[derive(Clone, Debug)]
pub struct QuoteSignatureData {
    /// ECDSA-P256-SHA256 signature over `header || body`, by the attestation
    /// key below.
    pub signature: [u8; EC_SIG_LEN],
    /// Raw uncompressed EC point (`x || y`, 32 bytes each) of the ephemeral
    /// attestation key the Quoting Enclave generated for this quote.
    pub attest_pub_key: [u8; EC_PUBKEY_LEN],
    /// The Quoting Enclave's own SGX report body (opaque at this layer — see
    /// module docs; [`crate::tee_verify`] reads its trailing `report_data`
    /// field to check the attestation-key binding).
    pub qe_report: [u8; QE_REPORT_LEN],
    /// ECDSA-P256-SHA256 signature over `qe_report`, by the PCK leaf
    /// certificate's key (the cert chain in `cert_data`).
    pub qe_report_sig: [u8; EC_SIG_LEN],
    pub qe_auth_data: Vec<u8>,
    pub cert_data: QeCertData,
}

/// A parsed TDX DCAP Quote, version 4.
///
/// `raw` retains the exact original bytes so a verifier signs/verifies the
/// SAME bytes that were parsed (no re-serialization round-trip that could
/// silently diverge from what the TD actually produced).
#[derive(Clone, Debug)]
pub struct TdQuoteV4 {
    pub header: TdQuoteHeader,
    pub body: TdQuoteBody,
    pub signature_data: QuoteSignatureData,
    raw: Vec<u8>,
}

impl TdQuoteV4 {
    /// The exact `header || body` bytes the quote signature in
    /// `signature_data.signature` was computed over.
    pub fn signed_bytes(&self) -> &[u8] {
        &self.raw[0..HEADER_LEN + BODY_LEN]
    }

    /// Parse a raw TDX DCAP v4 quote. Fixed-size header/body fields are
    /// read at their documented offsets; the variable-length signature/cert
    /// section is read length-prefixed, exactly as Intel's Quote Generation
    /// Library emits it.
    ///
    /// NOTE: offsets below follow the publicly documented Intel TDX DCAP
    /// Quote Generation Library layout. They are exercised here only against
    /// synthetic, self-encoded quotes (this module is the hardware-
    /// independent leg — see module docs); they have not yet been
    /// cross-checked against a quote captured from a real TDX platform. That
    /// cross-check is planned once the provisioned node is available and
    /// MUST happen before this parser is trusted against production quotes.
    pub fn parse(bytes: &[u8]) -> Result<Self, TeeQuoteError> {
        if bytes.len() < HEADER_LEN + BODY_LEN {
            return Err(TeeQuoteError::TooShort {
                need: HEADER_LEN + BODY_LEN,
                got: bytes.len(),
            });
        }
        let header = parse_header(&bytes[0..HEADER_LEN])?;
        let body = parse_body(&bytes[HEADER_LEN..HEADER_LEN + BODY_LEN]);
        let signature_data = parse_signature_data(&bytes[HEADER_LEN + BODY_LEN..])?;
        Ok(TdQuoteV4 {
            header,
            body,
            signature_data,
            raw: bytes.to_vec(),
        })
    }
}

fn u16_le(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}
fn u32_le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}
fn u64_le(b: &[u8]) -> u64 {
    u64::from_le_bytes(b.try_into().expect("8-byte slice"))
}
fn arr<const N: usize>(b: &[u8]) -> [u8; N] {
    b.try_into().expect("slice length checked by caller")
}

fn parse_header(b: &[u8]) -> Result<TdQuoteHeader, TeeQuoteError> {
    let version = u16_le(&b[0..2]);
    if version != 4 {
        return Err(TeeQuoteError::UnsupportedVersion(version));
    }
    let attestation_key_type = u16_le(&b[2..4]);
    let tee_type = u32_le(&b[4..8]);
    if tee_type != 0x0000_0081 {
        return Err(TeeQuoteError::UnsupportedTeeType(tee_type));
    }
    // b[8..12] reserved
    let qe_vendor_id = arr::<16>(&b[12..28]);
    let user_data = arr::<20>(&b[28..48]);
    Ok(TdQuoteHeader {
        version,
        attestation_key_type,
        tee_type,
        qe_vendor_id,
        user_data,
    })
}

fn parse_body(b: &[u8]) -> TdQuoteBody {
    let mut off = 0usize;
    macro_rules! take {
        ($n:expr) => {{
            let s = &b[off..off + $n];
            off += $n;
            s
        }};
    }
    let tee_tcb_svn = arr::<16>(take!(16));
    let mrseam = arr::<48>(take!(48));
    let mrsignerseam = arr::<48>(take!(48));
    let seam_attributes = u64_le(take!(8));
    let td_attributes = u64_le(take!(8));
    let xfam = u64_le(take!(8));
    let mrtd = arr::<48>(take!(48));
    let mrconfigid = arr::<48>(take!(48));
    let mrowner = arr::<48>(take!(48));
    let mrownerconfig = arr::<48>(take!(48));
    let mut rtmr = [[0u8; RTMR_LEN]; RTMR_COUNT];
    for slot in rtmr.iter_mut() {
        *slot = arr::<48>(take!(48));
    }
    let report_data = arr::<64>(take!(64));
    debug_assert_eq!(off, BODY_LEN, "body field layout must sum to BODY_LEN");
    TdQuoteBody {
        tee_tcb_svn,
        mrseam,
        mrsignerseam,
        seam_attributes,
        td_attributes,
        xfam,
        mrtd,
        mrconfigid,
        mrowner,
        mrownerconfig,
        rtmr,
        report_data,
    }
}

fn parse_signature_data(b: &[u8]) -> Result<QuoteSignatureData, TeeQuoteError> {
    // The quote wraps this whole section behind a u32 length prefix in the
    // wire format; callers here already sliced to "everything after
    // header+body", which Intel's library defines as exactly that length
    // prefix followed by the section itself.
    if b.len() < 4 {
        return Err(TeeQuoteError::TruncatedSignatureData("missing length prefix"));
    }
    let declared_len = u32_le(&b[0..4]) as usize;
    let section = &b[4..];
    if section.len() < declared_len {
        return Err(TeeQuoteError::TruncatedSignatureData(
            "section shorter than declared length",
        ));
    }
    let section = &section[..declared_len];

    let min_fixed = EC_SIG_LEN + EC_PUBKEY_LEN + QE_REPORT_LEN + EC_SIG_LEN + 2;
    if section.len() < min_fixed {
        return Err(TeeQuoteError::TruncatedSignatureData("fixed-size fields"));
    }
    let mut off = 0usize;
    let signature = arr::<EC_SIG_LEN>(&section[off..off + EC_SIG_LEN]);
    off += EC_SIG_LEN;
    let attest_pub_key = arr::<EC_PUBKEY_LEN>(&section[off..off + EC_PUBKEY_LEN]);
    off += EC_PUBKEY_LEN;
    let qe_report = arr::<QE_REPORT_LEN>(&section[off..off + QE_REPORT_LEN]);
    off += QE_REPORT_LEN;
    let qe_report_sig = arr::<EC_SIG_LEN>(&section[off..off + EC_SIG_LEN]);
    off += EC_SIG_LEN;

    let qe_auth_data_size = u16_le(&section[off..off + 2]) as usize;
    off += 2;
    if section.len() < off + qe_auth_data_size + 6 {
        return Err(TeeQuoteError::TruncatedSignatureData("qe_auth_data"));
    }
    let qe_auth_data = section[off..off + qe_auth_data_size].to_vec();
    off += qe_auth_data_size;

    let cert_data_type = u16_le(&section[off..off + 2]);
    off += 2;
    let cert_data_size = u32_le(&section[off..off + 4]) as usize;
    off += 4;
    if section.len() < off + cert_data_size {
        return Err(TeeQuoteError::TruncatedSignatureData("cert_data"));
    }
    if cert_data_type != 5 {
        return Err(TeeQuoteError::UnsupportedCertDataType(cert_data_type));
    }
    let pem_chain = section[off..off + cert_data_size].to_vec();
    // Validate UTF-8 eagerly (PEM is ASCII) so a malformed cert section fails
    // at parse time, not deep inside x509 parsing later.
    std::str::from_utf8(&pem_chain)?;

    Ok(QuoteSignatureData {
        signature,
        attest_pub_key,
        qe_report,
        qe_report_sig,
        qe_auth_data,
        cert_data: QeCertData {
            cert_data_type,
            pem_chain,
        },
    })
}

/// The capsule-facing `tee_measured` record: a parsed quote's measurement
/// registers plus the raw quote bytes a verifier independently re-parses and
/// re-verifies (never trust the extracted hex fields alone — they are a
/// convenience for a reader, not the evidence itself).
#[derive(Clone, Debug)]
pub struct TeeAttestation {
    pub measurement_class: MeasurementClass,
    /// `"tdx-dcap-v4"` — names the quote format so a future second HW path
    /// (e.g. SEV-SNP) can add its own tag without ambiguity.
    pub quote_format: String,
    /// The raw quote bytes exactly as obtained from the platform. This is
    /// the actual evidence; `mrtd`/`rtmr`/`report_data` below are a decoded
    /// convenience.
    pub quote: Vec<u8>,
    pub mrtd: String,
    pub rtmr: [String; RTMR_COUNT],
    pub report_data: String,
    /// The domain tag [`tee_binding_report_data`] used, so a verifier that
    /// receives this record knows which binding scheme to recompute.
    pub binding_domain_tag: String,
    /// Optional alternate evidence: an Intel Trust Authority attestation
    /// token (compact ES384 JWT) for the SAME quote, if the node also
    /// submitted it to ITA. `None` when only the local DCAP path was used —
    /// never a placeholder token.
    pub ita_token: Option<String>,
    pub measured_at: String,
}

impl TeeAttestation {
    /// Parse `quote` and build the record. Fails (never fabricates a
    /// best-effort partial record) if the quote does not parse as a TDX DCAP
    /// v4 quote — see [`TdQuoteV4::parse`].
    pub fn from_quote(
        quote: Vec<u8>,
        measured_at: String,
        ita_token: Option<String>,
    ) -> Result<Self, TeeQuoteError> {
        let parsed = TdQuoteV4::parse(&quote)?;
        Ok(TeeAttestation {
            measurement_class: MeasurementClass::TeeMeasured,
            quote_format: "tdx-dcap-v4".to_string(),
            mrtd: hex::encode(parsed.body.mrtd),
            rtmr: [
                hex::encode(parsed.body.rtmr[0]),
                hex::encode(parsed.body.rtmr[1]),
                hex::encode(parsed.body.rtmr[2]),
                hex::encode(parsed.body.rtmr[3]),
            ],
            report_data: hex::encode(parsed.body.report_data),
            binding_domain_tag: String::from_utf8_lossy(TEE_BINDING_DOMAIN_TAG).into_owned(),
            quote,
            ita_token,
            measured_at,
        })
    }

    /// The evidence-ref JSON object for the capsule's
    /// `evidence_refs.tee_attestation` slot (mirrors
    /// [`crate::runtime_attest::BinaryAttestation::to_value`]'s shape and
    /// honesty-labeling convention: the grade rides IN the record, not only
    /// in docs).
    pub fn to_value(&self) -> Value {
        json!({
            "type": "tee_attestation",
            "measurement_class": self.measurement_class.as_str(),
            "quote_format": self.quote_format,
            "quote": hex::encode(&self.quote),
            "mrtd": self.mrtd,
            "rtmr0": self.rtmr[0],
            "rtmr1": self.rtmr[1],
            "rtmr2": self.rtmr[2],
            "rtmr3": self.rtmr[3],
            "report_data": self.report_data,
            "binding_domain_tag": self.binding_domain_tag,
            "ita_token": self.ita_token,
            "measured_at": self.measured_at,
            "context": "tee-measured: MRTD/RTMR were measured and signed by the TDX \
module beneath the guest OS, not by the serving process. A root-compromised host \
cannot forge this the way it can forge a self_measured attestation. Does NOT prove \
Intel's DCAP PKI is uncompromised or that the platform's TCB is revocation-current \
(no live PCS/ITA freshness check performed by the record itself); see \
docs/REDTEAM-RUNG3.md.",
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Build a syntactically valid synthetic TDX DCAP v4 quote for tests: a
    /// real header+body+signature-section byte layout with test-chosen
    /// (not-hardware-derived) field values. Round-tripping through
    /// `TdQuoteV4::parse` is what these tests exercise — NOT authenticity
    /// against a real TDX platform (see module docs' offset caveat).
    pub(crate) fn synthetic_quote(
        report_data: [u8; REPORT_DATA_LEN],
        pem_chain: &[u8],
    ) -> (Vec<u8>, [u8; MRTD_LEN], [[u8; RTMR_LEN]; RTMR_COUNT]) {
        let mut mrtd = [0u8; MRTD_LEN];
        for (i, b) in mrtd.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut rtmr = [[0u8; RTMR_LEN]; RTMR_COUNT];
        for (r, slot) in rtmr.iter_mut().enumerate() {
            for (i, b) in slot.iter_mut().enumerate() {
                *b = (r * 10 + i) as u8;
            }
        }

        let mut out = Vec::new();
        // header
        out.extend_from_slice(&4u16.to_le_bytes()); // version
        out.extend_from_slice(&2u16.to_le_bytes()); // attestation_key_type
        out.extend_from_slice(&0x0000_0081u32.to_le_bytes()); // tee_type = TDX
        out.extend_from_slice(&[0u8; 4]); // reserved
        out.extend_from_slice(&[0xAB; 16]); // qe_vendor_id
        out.extend_from_slice(&[0xCD; 20]); // user_data
        assert_eq!(out.len(), HEADER_LEN);

        // body
        out.extend_from_slice(&[0u8; 16]); // tee_tcb_svn
        out.extend_from_slice(&[0u8; 48]); // mrseam
        out.extend_from_slice(&[0u8; 48]); // mrsignerseam
        out.extend_from_slice(&0u64.to_le_bytes()); // seam_attributes
        out.extend_from_slice(&0u64.to_le_bytes()); // td_attributes
        out.extend_from_slice(&0u64.to_le_bytes()); // xfam
        out.extend_from_slice(&mrtd); // mrtd
        out.extend_from_slice(&[0u8; 48]); // mrconfigid
        out.extend_from_slice(&[0u8; 48]); // mrowner
        out.extend_from_slice(&[0u8; 48]); // mrownerconfig
        for slot in rtmr.iter() {
            out.extend_from_slice(slot);
        }
        out.extend_from_slice(&report_data);
        assert_eq!(out.len(), HEADER_LEN + BODY_LEN);

        // signature section, length-prefixed
        let mut section = Vec::new();
        section.extend_from_slice(&[0x11; EC_SIG_LEN]); // signature
        section.extend_from_slice(&[0x22; EC_PUBKEY_LEN]); // attest_pub_key
        section.extend_from_slice(&[0x33; QE_REPORT_LEN]); // qe_report
        section.extend_from_slice(&[0x44; EC_SIG_LEN]); // qe_report_sig
        section.extend_from_slice(&0u16.to_le_bytes()); // qe_auth_data_size
        section.extend_from_slice(&5u16.to_le_bytes()); // cert_data_type = 5
        section.extend_from_slice(&(pem_chain.len() as u32).to_le_bytes());
        section.extend_from_slice(pem_chain);

        out.extend_from_slice(&(section.len() as u32).to_le_bytes());
        out.extend_from_slice(&section);
        (out, mrtd, rtmr)
    }

    #[test]
    fn parses_synthetic_quote_and_extracts_measurement_registers() {
        let report_data = tee_binding_report_data(b"capsule-digest-bytes", b"nonce-bytes");
        let (bytes, mrtd, rtmr) = synthetic_quote(report_data, b"dummy pem chain");
        let q = TdQuoteV4::parse(&bytes).expect("synthetic quote parses");
        assert_eq!(q.header.version, 4);
        assert_eq!(q.header.tee_type, 0x0000_0081);
        assert_eq!(q.body.mrtd, mrtd);
        assert_eq!(q.body.rtmr, rtmr);
        assert_eq!(q.body.report_data, report_data);
        assert_eq!(q.signature_data.cert_data.pem_chain, b"dummy pem chain");
        assert_eq!(q.signed_bytes().len(), HEADER_LEN + BODY_LEN);
    }

    #[test]
    fn rejects_wrong_version_and_wrong_tee_type() {
        let report_data = [0u8; REPORT_DATA_LEN];
        let (mut bytes, _, _) = synthetic_quote(report_data, b"x");
        bytes[0] = 3; // version 3, not 4
        assert!(matches!(
            TdQuoteV4::parse(&bytes),
            Err(TeeQuoteError::UnsupportedVersion(3))
        ));

        let (mut bytes2, _, _) = synthetic_quote(report_data, b"x");
        bytes2[4..8].copy_from_slice(&0u32.to_le_bytes()); // SGX tee_type
        assert!(matches!(
            TdQuoteV4::parse(&bytes2),
            Err(TeeQuoteError::UnsupportedTeeType(0))
        ));
    }

    #[test]
    fn rejects_truncated_quote() {
        let err = TdQuoteV4::parse(&[0u8; 10]).unwrap_err();
        assert!(matches!(err, TeeQuoteError::TooShort { .. }));
    }

    #[test]
    fn tee_attestation_from_quote_carries_measurement_class_and_hex_fields() {
        let report_data = tee_binding_report_data(b"digest", b"nonce");
        let (bytes, mrtd, _rtmr) = synthetic_quote(report_data, b"pem");
        let att = TeeAttestation::from_quote(bytes, "2026-08-31T00:00:00Z".to_string(), None)
            .expect("valid synthetic quote builds a record");
        assert_eq!(att.measurement_class, MeasurementClass::TeeMeasured);
        assert_eq!(att.measurement_class.as_str(), "tee_measured");
        assert_eq!(att.mrtd, hex::encode(mrtd));
        assert_eq!(att.report_data, hex::encode(report_data));
        assert!(att.ita_token.is_none());

        let v = att.to_value();
        assert_eq!(v["measurement_class"], "tee_measured");
        assert_eq!(v["type"], "tee_attestation");
        assert!(v["context"].as_str().unwrap().contains("tee-measured"));
        assert!(v["context"]
            .as_str()
            .unwrap()
            .contains("root-compromised host"));
    }

    #[test]
    fn binding_report_data_is_deterministic_and_input_sensitive() {
        let a = tee_binding_report_data(b"digest-A", b"nonce-1");
        let a_again = tee_binding_report_data(b"digest-A", b"nonce-1");
        let b = tee_binding_report_data(b"digest-B", b"nonce-1");
        let c = tee_binding_report_data(b"digest-A", b"nonce-2");
        assert_eq!(a, a_again, "same inputs must yield the same REPORTDATA");
        assert_ne!(a, b, "different capsule digest must change REPORTDATA");
        assert_ne!(a, c, "different nonce must change REPORTDATA");
        assert_eq!(a.len(), REPORT_DATA_LEN);
    }
}
