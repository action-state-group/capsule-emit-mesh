//! COSE_Sign1 producer (RFC 9052 §4.4), matching the wire shape of
//! `scitt_cose.statement.build_signed_statement` / `cose_sign1.sign_sign1`:
//! protected header carries alg (label 1, forced to EdDSA/-8), content_type
//! (label 3), and a CWT Claims map (label 15, RFC 9597) with issuer (claim 1)
//! and subject (claim 2); unprotected header is empty; payload is attached
//! (not detached). Built with the `coset` crate over `ed25519-dalek`.

use coset::cbor::value::Value as CborValue;
use coset::{CoseSign1, CoseSign1Builder, HeaderBuilder, TaggedCborSerializable};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};

/// RFC 9597 §2 "CWT Claims" protected-header label. NOT label 13 (kcwt,
/// RFC 9528) — the scitt-cose Python reference calls this out explicitly
/// because it is the exact bug class this crate must not repeat.
const HDR_CWT_CLAIMS: i64 = 15;
const CWT_ISS: i64 = 1;
const CWT_SUB: i64 = 2;

pub struct SignedStatementInput<'a> {
    pub payload: &'a [u8],
    pub issuer: &'a str,
    pub subject: &'a str,
    pub content_type: &'a str,
}

/// Build a generic SCITT Signed Statement (COSE_Sign1) over `payload`, signed
/// with `signing_key`. Returns CBOR tag-18 bytes — the same shape
/// `scitt_cose.build_signed_statement` produces.
pub fn build_signed_statement(input: &SignedStatementInput, signing_key: &SigningKey) -> Vec<u8> {
    let claims = CborValue::Map(vec![
        (
            CborValue::Integer(CWT_ISS.into()),
            CborValue::Text(input.issuer.to_string()),
        ),
        (
            CborValue::Integer(CWT_SUB.into()),
            CborValue::Text(input.subject.to_string()),
        ),
    ]);

    let protected = HeaderBuilder::new()
        .algorithm(coset::iana::Algorithm::EdDSA)
        .content_type(input.content_type.to_string())
        .value(HDR_CWT_CLAIMS, claims)
        .build();

    let sign1 = CoseSign1Builder::new()
        .protected(protected)
        .payload(input.payload.to_vec())
        .create_signature(b"", |tbs| signing_key.sign(tbs).to_bytes().to_vec())
        .build();

    sign1
        .to_tagged_vec()
        .expect("COSE_Sign1 must always be CBOR-serializable")
}

pub struct VerifiedStatement {
    pub payload: Vec<u8>,
    pub issuer: Option<String>,
    pub subject: Option<String>,
    pub content_type: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("CBOR decode error: {0}")]
    Decode(String),
    #[error("message has no attached payload (detached payloads not supported here)")]
    NoPayload,
    #[error("signature verification failed")]
    BadSignature,
}

/// Verify a COSE_Sign1 signed statement and return its payload + CWT claims.
/// A second, independent verifier (alongside the Python/Go ones) so a producer
/// bug isn't masked by re-parsing with the same code that built it.
pub fn verify_signed_statement(
    msg: &[u8],
    verifying_key: &VerifyingKey,
) -> Result<VerifiedStatement, VerifyError> {
    let sign1 =
        CoseSign1::from_tagged_slice(msg).map_err(|e| VerifyError::Decode(e.to_string()))?;

    let result = sign1.verify_signature(b"", |sig, tbs| {
        let sig_bytes: [u8; 64] = sig.try_into().map_err(|_| VerifyError::BadSignature)?;
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        verifying_key
            .verify(tbs, &signature)
            .map_err(|_| VerifyError::BadSignature)
    });
    result?;

    let payload = sign1.payload.clone().ok_or(VerifyError::NoPayload)?;

    let protected = &sign1.protected.header;
    let content_type = match &protected.content_type {
        Some(coset::RegisteredLabel::Text(s)) => Some(s.clone()),
        _ => None,
    };
    let claims = protected
        .rest
        .iter()
        .find(|(label, _)| *label == coset::Label::Int(HDR_CWT_CLAIMS))
        .map(|(_, v)| v.clone());
    let (issuer, subject) = match claims {
        Some(CborValue::Map(entries)) => {
            let get = |want: i64| {
                entries.iter().find_map(|(k, v)| match (k, v) {
                    (CborValue::Integer(i), CborValue::Text(s))
                        if i128::from(*i) == want as i128 =>
                    {
                        Some(s.clone())
                    }
                    _ => None,
                })
            };
            (get(CWT_ISS), get(CWT_SUB))
        }
        _ => (None, None),
    };

    Ok(VerifiedStatement {
        payload,
        issuer,
        subject,
        content_type,
    })
}
