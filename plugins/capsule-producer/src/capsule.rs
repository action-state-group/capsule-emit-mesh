//! Milestone 1 AAC data model: just enough of the Capsule envelope
//! (draft-mih-scitt-agent-action-capsule-02 §5.1) to emit ONE valid,
//! self-attested capsule with an `x-mesh-poc-v1` compute-attestation extension —
//! mirroring `agent_action_capsule.emit.emit()` /
//! `capsule_sidecar.build_capsule()` closely enough for cross-language byte
//! conformance, without the sidecar's live-proxy state (forwarded_copy,
//! cross_party, bilateral evaluation) or chaining/ledger, which are later
//! milestones per the task.

use crate::jcs::compute_capsule_id;
use serde_json::{json, Map, Value};

pub const SPEC_VERSION: &str = "draft-mih-scitt-agent-action-capsule-02";
pub const FORMAT_VERSION: &str = "2";

/// The PoC-only `x-mesh-poc-v1` extension namespace inside
/// `model_attestation.compute_attestation` (see capsule-emit-mesh README
/// "Field mapping"). Not a registered spec field — rides inside
/// `compute_attestation`, which is documented as a free-form best-effort dict.
pub struct MeshPocV1 {
    pub client_nonce: String,
    pub client_nonce_source: String,
    pub model_package_digest: String,
    /// Generation parameters as exact decimal STRINGS (§5.1 forbids floats in
    /// digest-bearing fields) — e.g. `{"temperature": "0.7"}`.
    pub generation_parameters: Map<String, Value>,
    pub latency_ms: String,
}

impl MeshPocV1 {
    fn to_value(&self) -> Value {
        json!({
            "client_nonce": self.client_nonce,
            "client_nonce_source": self.client_nonce_source,
            "model_package_digest": self.model_package_digest,
            "generation_parameters": self.generation_parameters,
            "latency_ms": self.latency_ms,
            // Typed reference fields, present-but-empty (issue #1233 steps 4/5 —
            // statistical fingerprint / TEE evidence — are future work that
            // upgrades these slots without changing the record shape).
            "evidence_refs": {
                "statistical_fingerprint": {"type": "statistical_fingerprint", "digest": null, "context": null},
                "tee_attestation": {"type": "tee_attestation", "digest": null, "context": null},
            },
        })
    }
}

pub struct CapsuleInput {
    pub action_id: String,
    pub action_type: String,
    pub operator: String,
    pub developer: String,
    pub timestamp: String,
    pub domain: Option<String>,
    pub provenance: Option<String>,
    pub model_id: String,
    pub provider: String,
    pub agent_input_digest: String,
    pub agent_output_digest: String,
    pub runtime: String,
    pub mesh_poc: MeshPocV1,
    pub effect_status: String,
    pub effect_type: String,
    pub effect_request_digest: String,
    pub effect_response_digest: String,
    pub effect_attestation: String,
    pub disposition_decision: String,
    pub disposition_approver: String,
    pub disposition_human_disposed: bool,
    pub disposition_verdict_class: String,
}

/// derive_effect_mode (contracts.py) for the subset this milestone emits:
/// status "confirmed" with a well-formed (64-hex) response_digest -> "confirmed".
fn derive_effect_mode(status: &str, response_digest: &str) -> &'static str {
    let is_hex64 = response_digest.len() == 64
        && response_digest
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase());
    match status {
        "planned" => "not_applicable",
        "confirmed" if is_hex64 => "confirmed",
        "confirmed" => "dispatched_unconfirmed",
        _ => "dispatched_unconfirmed",
    }
}

/// Build and seal a Capsule (mirrors `emit.emit()` + `parse.Capsule.seal()`):
/// returns the full capsule dict with `capsule_id` computed over the canonical
/// capsule form (§5.1) — standalone (no `chain` block; chaining is milestone 2).
pub fn seal(input: &CapsuleInput) -> Result<Value, crate::jcs::JcsError> {
    let mut body = Map::new();
    body.insert("spec_version".into(), json!(SPEC_VERSION));
    body.insert("format_version".into(), json!(FORMAT_VERSION));
    body.insert("action_id".into(), json!(input.action_id));
    body.insert("action_type".into(), json!(input.action_type));
    body.insert("operator".into(), json!(input.operator));
    body.insert("developer".into(), json!(input.developer));
    body.insert("timestamp".into(), json!(input.timestamp));
    if let Some(d) = &input.domain {
        body.insert("domain".into(), json!(d));
    }
    if let Some(p) = &input.provenance {
        body.insert("provenance".into(), json!(p));
    }
    body.insert(
        "model_attestation".into(),
        json!({
            "model_id": input.model_id,
            "provider": input.provider,
            "compute_attestation": {
                "agent_input_digest": input.agent_input_digest,
                "agent_output_digest": input.agent_output_digest,
                "runtime": input.runtime,
                "x-mesh-poc-v1": input.mesh_poc.to_value(),
            },
        }),
    );
    body.insert(
        "effect".into(),
        json!({
            "status": input.effect_status,
            "type": input.effect_type,
            "request_digest": input.effect_request_digest,
            "response_digest": input.effect_response_digest,
            "effect_attestation": input.effect_attestation,
        }),
    );
    let effect_mode = derive_effect_mode(&input.effect_status, &input.effect_response_digest);
    body.insert(
        "assurance".into(),
        json!({
            "attestation_mode": "self_attested",
            "effect_mode": effect_mode,
            "ledger_mode": "standalone",
        }),
    );
    body.insert(
        "disposition".into(),
        json!({
            "decision": input.disposition_decision,
            "approver": input.disposition_approver,
            "human_disposed": input.disposition_human_disposed,
            "verdict_class": input.disposition_verdict_class,
        }),
    );

    let body_value = Value::Object(body.clone());
    let capsule_id = compute_capsule_id(&body_value)?;

    let mut sealed = Map::new();
    sealed.insert("spec_version".into(), json!(SPEC_VERSION));
    sealed.insert("format_version".into(), json!(FORMAT_VERSION));
    sealed.insert("capsule_id".into(), json!(capsule_id));
    for (k, v) in body {
        sealed.entry(k).or_insert(v);
    }
    Ok(Value::Object(sealed))
}

/// The bytes signed by COSE_Sign1 and carried as the COSE payload. The Python
/// sidecar signs `json.dumps(capsule, sort_keys=True, separators=(",", ":"))` —
/// deterministic but NOT JCS (`capsule_id` is what's JCS-canonicalized; this is
/// just a transport encoding of the already-sealed capsule). Byte-for-byte
/// parity with Python's own sort_keys+ensure_ascii output is not required for
/// conformance: `verify()` re-parses the payload as JSON and recomputes
/// `capsule_id` from the parsed object, independent of how it was serialized.
/// Compact JSON is sufficient here.
pub fn payload_bytes(capsule: &Value) -> Vec<u8> {
    serde_json::to_vec(capsule).expect("capsule must be JSON-serializable")
}
