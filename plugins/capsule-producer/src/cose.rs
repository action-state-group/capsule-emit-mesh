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

/// The frozen AAC producer-envelope content type (COSE protected header label
/// 3), matching `agent_action_capsule.media_types.CAPSULE_ID_MEDIA_TYPE` and
/// `capsule_emit.signing.LocalKeypairSigner.sign_envelope`. The envelope's
/// payload is the raw 32-byte `capsule_id` digest under this media type.
pub const CAPSULE_ID_MEDIA_TYPE: &str = "application/agent-action-capsule-id";

/// Build the frozen AAC **producer envelope** — the inline self-attested
/// signature `capsule_emit.seal()`/`emit()` attaches as `capsule["signature"]`
/// — over the raw 32-byte `capsule_id` digest.
///
/// This mirrors `capsule_emit.signing.LocalKeypairSigner.sign_envelope`
/// (the Python reference) field-for-field: a COSE_Sign1 (CBOR tag 18) whose
/// protected header carries exactly `{alg (label 1) = EdDSA (-8), content_type
/// (label 3) = "application/agent-action-capsule-id", kid (label 4) = the raw
/// 32-byte Ed25519 public key}`, an empty unprotected header, and the raw
/// 32-byte digest as an ATTACHED payload. Built with `coset` (boundary rule:
/// no hand-rolled COSE), the same crate `build_signed_statement` uses.
///
/// **Wire-byte note (verifier-parity, not byte-parity).** `coset` serializes
/// the protected-header map in canonical CBOR label order (1, 3, 4) — which
/// RFC 9052 §9 REQUIRES — whereas the Python `scitt_cose.cose_sign1.sign_sign1`
/// reference emits it in insertion order (3, 4, 1, because it appends the forced
/// `alg` last), a §9 violation. The two envelopes therefore differ byte-for-byte
/// and carry different (but each internally-valid) signatures. This is harmless
/// and by design, because label order CANNOT affect the signature check: both
/// verification doors feed the protected-header bstr into the `Sig_structure`
/// EXACTLY AS RECEIVED — the signature is byte-exact over the original protected
/// bytes, so whatever order the producer emitted is precisely what is verified.
/// The protected map is re-parsed ONLY to READ alg / content_type / key_id (and,
/// for a signed statement, the CWT claims) out of the header — never to
/// reconstruct the signed bytes. This is verified from source on BOTH doors:
///
/// - **Rust door** (`verify_signed_statement`, below): verification runs through
///   `coset`'s `sign1.verify_signature`, which builds the `Sig_structure` from
///   the protected header's PRESERVED ORIGINAL bytes (as received on parse). The
///   protected map is re-parsed only to read alg / content_type / key_id / CWT
///   claims — never to rebuild the signed bytes.
/// - **Python door** (`scitt_cose/cose_sign1.py::verify_sign1`): `protected_bstr`
///   comes out of `_decode_envelope(msg)` (line ~309) as RAW bytes (kept raw at
///   line ~313), and `tbs = _sig_structure(protected_bstr, payload)` (line ~354)
///   signs over that AS-RECEIVED bstr. `cbor2.loads(protected_bstr)` (line ~319)
///   decodes the map ONLY to read alg / kid / content-type / claims, never for
///   the signature; `strict_decode` is deliberately order-tolerant (a key
///   re-ordering preserves length and is accepted — cose_sign1.py ~line 195-197).
///
/// A `coset`-built envelope therefore verifies GREEN against the same Python
/// reference the door uses. Making the bytes identical would require
/// hand-emitting the CBOR map in the non-canonical Python order, which `coset`
/// cannot do and which the no-hand-rolled-COSE boundary rule forbids.
pub fn sign_producer_envelope(capsule_id_digest: &[u8], signing_key: &SigningKey) -> Vec<u8> {
    let public_key = signing_key.verifying_key().to_bytes().to_vec();
    let protected = HeaderBuilder::new()
        .algorithm(coset::iana::Algorithm::EdDSA)
        .content_type(CAPSULE_ID_MEDIA_TYPE.to_string())
        .key_id(public_key)
        .build();

    let sign1 = CoseSign1Builder::new()
        .protected(protected)
        .payload(capsule_id_digest.to_vec())
        .create_signature(b"", |tbs| signing_key.sign(tbs).to_bytes().to_vec())
        .build();

    sign1
        .to_tagged_vec()
        .expect("COSE_Sign1 must always be CBOR-serializable")
}

/// Verify a capsule's inline producer envelope (`signature` + `key_id`, as
/// `attach_producer_envelope` or the Python `sign_producer_envelope` attach
/// them): the `capsule_id` recomputes, the envelope's payload is that id's raw
/// digest, its kid is the carried `key_id`, and the signature verifies under
/// that key. Returns the signing `key_id` (hex) on success.
pub fn verify_producer_envelope(capsule: &serde_json::Value) -> Result<String, String> {
    let carried = capsule
        .get("capsule_id")
        .and_then(serde_json::Value::as_str)
        .ok_or("no capsule_id")?;
    let recomputed = crate::jcs::compute_capsule_id(capsule).map_err(|e| format!("capsule_id: {e}"))?;
    if recomputed != carried {
        return Err("capsule_id does not recompute".into());
    }
    let key_id = capsule
        .get("key_id")
        .and_then(serde_json::Value::as_str)
        .ok_or("no key_id")?;
    let signature = capsule
        .get("signature")
        .and_then(serde_json::Value::as_str)
        .ok_or("no signature")?;
    let key_bytes: [u8; 32] = hex::decode(key_id)
        .map_err(|_| "key_id is not hex")?
        .try_into()
        .map_err(|_| "key_id is not 32 bytes")?;
    let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| "key_id is not an Ed25519 key")?;
    let envelope = hex::decode(signature).map_err(|_| "signature is not hex")?;
    let sign1 = CoseSign1::from_tagged_slice(&envelope).map_err(|_| "signature is not a COSE_Sign1")?;
    if sign1.protected.header.key_id != key_bytes.to_vec() {
        return Err("envelope kid is not the carried key_id".into());
    }
    let digest = hex::decode(carried).map_err(|_| "capsule_id is not hex")?;
    if sign1.payload.as_deref() != Some(&digest[..]) {
        return Err("envelope payload is not this capsule_id".into());
    }
    sign1
        .verify_signature(b"", |sig, tbs| {
            let sig: [u8; 64] = sig.try_into().map_err(|_| ed25519_dalek::SignatureError::new())?;
            key.verify(tbs, &ed25519_dalek::Signature::from_bytes(&sig))
        })
        .map_err(|_| "signature does not verify")?;
    Ok(key_id.to_string())
}

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

/// Decode a COSE_Sign1 signed statement and return its attached payload
/// WITHOUT verifying the signature -- for a caller that has no verifying key
/// (e.g. `Ledger::open`'s reload check over a capsule that carries no inline
/// `key_id`) but still needs to know the statement is a parseable COSE_Sign1
/// whose payload names the right capsule. Never a substitute for
/// [`verify_signed_statement`] where a key IS available.
pub fn statement_payload(msg: &[u8]) -> Result<Vec<u8>, VerifyError> {
    let sign1 =
        CoseSign1::from_tagged_slice(msg).map_err(|e| VerifyError::Decode(e.to_string()))?;
    sign1.payload.ok_or(VerifyError::NoPayload)
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

#[cfg(test)]
mod tests {
    use super::*;
    use coset::CoseSign1;

    /// The inline producer envelope [`sign_producer_envelope`] builds MUST have
    /// exactly the frozen AAC producer-envelope protected header
    /// (`agent_action_capsule.producer_envelope`): alg EdDSA (-8, label 1),
    /// content_type "application/agent-action-capsule-id" (label 3), kid = the
    /// raw 32-byte public key (label 4); an empty unprotected header; and the
    /// raw 32-byte digest as the ATTACHED payload -- and it MUST self-verify.
    #[test]
    fn producer_envelope_has_the_frozen_protected_header_and_self_verifies() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = sk.verifying_key();
        let digest = [9u8; 32];
        let envelope = sign_producer_envelope(&digest, &sk);

        let sign1 = CoseSign1::from_tagged_slice(&envelope).expect("valid COSE_Sign1 tag 18");

        // alg = EdDSA (-8, label 1)
        assert_eq!(
            sign1.protected.header.alg,
            Some(coset::RegisteredLabelWithPrivate::Assigned(
                coset::iana::Algorithm::EdDSA
            ))
        );
        // content_type = the AAC capsule-id media type (label 3)
        assert_eq!(
            sign1.protected.header.content_type,
            Some(coset::RegisteredLabel::Text(CAPSULE_ID_MEDIA_TYPE.to_string()))
        );
        // kid = the raw 32-byte public key (label 4)
        assert_eq!(sign1.protected.header.key_id, vk.to_bytes().to_vec());
        // no other protected params (label set is exactly {1,3,4})
        assert!(
            sign1.protected.header.rest.is_empty(),
            "protected header MUST carry only alg, content_type, and kid"
        );
        // empty unprotected header
        assert!(sign1.unprotected == coset::Header::default());
        // attached payload == the raw 32-byte digest
        assert_eq!(sign1.payload.as_deref(), Some(&digest[..]));

        // self-verifies against the signing key
        sign1
            .verify_signature(b"", |sig, tbs| {
                let sig_bytes: [u8; 64] = sig.try_into().unwrap();
                vk.verify(tbs, &ed25519_dalek::Signature::from_bytes(&sig_bytes))
            })
            .expect("producer envelope must self-verify");
    }

    /// A DIFFERENT key produces a DIFFERENT signature/kid -- the envelope is
    /// bound to the actual signer, never a fixed value.
    #[test]
    fn producer_envelope_is_bound_to_the_signing_key() {
        let digest = [3u8; 32];
        let a = sign_producer_envelope(&digest, &SigningKey::from_bytes(&[1u8; 32]));
        let b = sign_producer_envelope(&digest, &SigningKey::from_bytes(&[2u8; 32]));
        assert_ne!(a, b);
    }

    fn enveloped(sk: &SigningKey) -> serde_json::Value {
        let mut capsule = serde_json::json!({ "schema": "t", "body": { "n": 1 } });
        let id = crate::jcs::compute_capsule_id(&capsule).unwrap();
        capsule["capsule_id"] = serde_json::json!(id);
        let envelope = sign_producer_envelope(&hex::decode(&id).unwrap(), sk);
        capsule["signature"] = serde_json::json!(hex::encode(envelope));
        capsule["key_id"] = serde_json::json!(hex::encode(sk.verifying_key().to_bytes()));
        capsule
    }

    #[test]
    fn a_producer_envelope_verifies_and_names_its_key() {
        let sk = SigningKey::from_bytes(&[5u8; 32]);
        let capsule = enveloped(&sk);
        assert_eq!(verify_producer_envelope(&capsule).unwrap(), hex::encode(sk.verifying_key().to_bytes()));
    }

    #[test]
    fn an_altered_or_resigned_capsule_does_not_verify() {
        let sk = SigningKey::from_bytes(&[5u8; 32]);
        let mut altered = enveloped(&sk);
        altered["body"]["n"] = serde_json::json!(2);
        assert!(verify_producer_envelope(&altered).is_err(), "content changed");

        let mut other_key = enveloped(&sk);
        other_key["key_id"] = serde_json::json!(hex::encode(SigningKey::from_bytes(&[6u8; 32]).verifying_key().to_bytes()));
        assert!(verify_producer_envelope(&other_key).is_err(), "key_id swapped");

        let mut unsigned = enveloped(&sk);
        unsigned.as_object_mut().unwrap().remove("signature");
        assert!(verify_producer_envelope(&unsigned).is_err(), "unsigned");
    }

}
