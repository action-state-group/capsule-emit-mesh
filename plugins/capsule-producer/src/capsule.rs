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

/// Token accounting for one exchange, sourced verbatim from the OpenAI-shaped
/// response body's `usage` object (`openai-frontend`'s `Usage`:
/// `prompt_tokens`/`completion_tokens`/`total_tokens`). `None` when the served
/// response carried no `usage` (e.g. a stub or error body) — never fabricated.
#[derive(Clone)]
pub struct TokenUsage {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
}

/// Everything we can HONESTLY attest about *what ran where* for one exchange.
/// Every field here is either (a) a real value the host/response actually
/// exposed, or (b) an explicit `"unknown"`/`null` for a fact the host's
/// `openai.exchange.v1` event and OpenAI-shaped response body genuinely do NOT
/// carry. It is deliberately truthful about the second class: we do not invent
/// a quantization or GPU string the mesh-llm host never told us.
///
/// What the host DOES expose to this plugin (verified against
/// `mesh-llm/…/plugin/openai_exchange.rs` on the `mesh1331-lifecycle-hooks`
/// branch and `openai-frontend`'s `ChatCompletionResponse`):
///
/// - `model` (the served model NAME) — already in `model_attestation.model_id`
/// - `usage` (prompt/completion/total tokens) — in the response body
/// - `exchange_id` / a per-exchange correlation id, `nonce`, `nonce_source`,
///   `capsule_id` marker, `status`, `dispatch_path` — on the lifecycle event
/// - the emitting node's own id — this plugin's `node_id`
///
/// What it does NOT expose (so these stay `"unknown"`/`null`):
///
/// - `quantization` — lives only in the TUI/`mesh-llm-system` crates; never
///   surfaced on the exchange channel or in the response body.
/// - hardware (GPU model / VRAM / device) — same: `mesh-llm-system` has it,
///   but it is never carried on the event this plugin observes.
/// - a serving-peer node id DISTINCT from the requester — the PoC serves and
///   requests from the same node, so `served_by_node_id` is that one node.
#[derive(Clone)]
pub struct ServingProvenance {
    /// The node that actually served the inference. In this single-node PoC it
    /// is the emitting plugin's own `node_id`; a multi-hop mesh would carry the
    /// distinct serving peer here (the host event does not yet expose one).
    pub served_by_node_id: String,
    /// The requesting party / client identity for this exchange. `"unknown"`
    /// when the caller supplied no identity beyond the (optional) client nonce.
    pub requesting_party: String,
    /// Stable per-exchange correlation id (the host's `exchange_id` /
    /// response `id` / `x-request-id` lineage), so this record can be tied back
    /// to the host's own terminal-event log for the same exchange.
    pub exchange_id: String,
    /// Model QUANTIZATION (e.g. "Q4_K_M"). The mesh-llm host does NOT expose
    /// this on the exchange event or in the response body, so it is recorded as
    /// `"unknown"` here rather than guessed. Populated only if a future host
    /// event carries it.
    pub quantization: String,
    /// Serving hardware. All `null` today: the host does not carry GPU/VRAM/
    /// device on the event this plugin observes. Never fabricated.
    pub hardware_gpu: Option<String>,
    pub hardware_vram_bytes: Option<u64>,
    pub hardware_device: Option<String>,
    /// Token accounting from the response `usage`, or `None` if absent.
    pub usage: Option<TokenUsage>,
}

impl ServingProvenance {
    fn to_value(&self) -> Value {
        let usage = match &self.usage {
            Some(u) => json!({
                "prompt_tokens": u.prompt_tokens,
                "completion_tokens": u.completion_tokens,
                "total_tokens": u.total_tokens,
            }),
            None => Value::Null,
        };
        json!({
            "served_by_node_id": self.served_by_node_id,
            "requesting_party": self.requesting_party,
            "exchange_id": self.exchange_id,
            // Host does not expose quantization on the exchange event today.
            "quantization": self.quantization,
            // Host does not expose serving hardware on the exchange event today.
            "hardware": {
                "gpu": self.hardware_gpu,
                "vram_bytes": self.hardware_vram_bytes,
                "device": self.hardware_device,
            },
            "usage": usage,
        })
    }
}

/// The PoC-only `x-mesh-poc-v1` extension namespace inside
/// `model_attestation.compute_attestation` (see capsule-emit-mesh README
/// "Field mapping"). Not a registered spec field — rides inside
/// `compute_attestation`, which is documented as a free-form best-effort dict.
pub struct MeshPocV1 {
    pub client_nonce: String,
    pub client_nonce_source: String,
    /// SHA-256 of the model NAME string only — NOT a digest of the model
    /// weights or package. Named truthfully (`model_name_digest`) so it never
    /// implies weight/artifact binding it does not provide. The real
    /// package-digest path (issue #1233's `sha256(manifest+artifacts+abi)`)
    /// is the Python `model_identity.py` producer; the live Rust plugin only
    /// has the request's model name, so it attests exactly that and no more.
    pub model_name_digest: String,
    /// Detailed serving provenance: what ran where, for which exchange.
    pub serving_provenance: ServingProvenance,
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
            "model_name_digest": self.model_name_digest,
            "serving_provenance": self.serving_provenance.to_value(),
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

/// `chain.parent_capsule_id`/`relation` (draft-mih-scitt-agent-action-capsule-02
/// §5.1, `Chain` in `agent_action_capsule.contracts`). Excluded from the
/// `capsule_id` digest by `jcs::CHAIN_LINKAGE_FIELDS` (mirrors
/// `canonical.CHAIN_LINKAGE_FIELDS`), so a capsule's content-address never
/// depends on what later chains to it.
pub struct ChainLink {
    pub parent_capsule_id: String,
    pub relation: String,
}

impl ChainLink {
    fn to_value(&self) -> Value {
        json!({
            "parent_capsule_id": self.parent_capsule_id,
            "relation": self.relation,
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
    /// `None` for the first capsule in a chain — mirrors `emit()`'s
    /// `prior_capsule_id=None` (no `chain` key at all, not a null value).
    pub chain: Option<ChainLink>,
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
    // ledger_mode mirrors emit.py: "chained" iff a chain block is present,
    // "standalone" otherwise -- NOT a statement about whether this producer
    // happens to also be writing to a local ledger file.
    let ledger_mode = if input.chain.is_some() {
        "chained"
    } else {
        "standalone"
    };
    body.insert(
        "assurance".into(),
        json!({
            "attestation_mode": "self_attested",
            "effect_mode": effect_mode,
            "ledger_mode": ledger_mode,
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
    if let Some(chain) = &input.chain {
        body.insert("chain".into(), chain.to_value());
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    fn base_input(chain: Option<ChainLink>) -> CapsuleInput {
        let mut generation_parameters = Map::new();
        generation_parameters.insert("temperature".into(), json!("0.7"));
        CapsuleInput {
            action_id: "mesh-poc/chain-test/1".to_string(),
            action_type: "decide".to_string(),
            operator: "op".to_string(),
            developer: "dev".to_string(),
            timestamp: "2026-08-23T00:00:00Z".to_string(),
            domain: Some("action".to_string()),
            provenance: Some("collector".to_string()),
            model_id: "m".to_string(),
            provider: "p".to_string(),
            agent_input_digest: "a".repeat(64),
            agent_output_digest: "b".repeat(64),
            runtime: "runtime".to_string(),
            mesh_poc: MeshPocV1 {
                client_nonce: "c".repeat(32),
                client_nonce_source: "client_supplied".to_string(),
                model_name_digest: "d".repeat(64),
                serving_provenance: ServingProvenance {
                    served_by_node_id: "node-under-test".to_string(),
                    requesting_party: "client-under-test".to_string(),
                    exchange_id: "exch-under-test".to_string(),
                    quantization: "unknown".to_string(),
                    hardware_gpu: None,
                    hardware_vram_bytes: None,
                    hardware_device: None,
                    usage: Some(TokenUsage {
                        prompt_tokens: 11,
                        completion_tokens: 22,
                        total_tokens: 33,
                    }),
                },
                generation_parameters,
                latency_ms: "1.0".to_string(),
            },
            effect_status: "confirmed".to_string(),
            effect_type: "inference_completion".to_string(),
            effect_request_digest: "a".repeat(64),
            effect_response_digest: "b".repeat(64),
            effect_attestation: "gate_executed".to_string(),
            disposition_decision: "accept".to_string(),
            disposition_approver: "policy".to_string(),
            disposition_human_disposed: false,
            disposition_verdict_class: "executed".to_string(),
            chain,
        }
    }

    /// The `x-mesh-poc-v1` extension's serving-provenance sub-object of one
    /// sealed capsule.
    fn provenance(capsule: &Value) -> &Value {
        &capsule["model_attestation"]["compute_attestation"]["x-mesh-poc-v1"]
            ["serving_provenance"]
    }

    /// The enriched capsule carries EVERY provenance field the host exposes,
    /// under `x-mesh-poc-v1.serving_provenance`, plus the truthfully-renamed
    /// `model_name_digest`. This is the record that must answer "which model,
    /// at what quantization, on whose hardware, for which exchange".
    #[test]
    fn capsule_carries_full_serving_provenance() {
        let capsule = seal(&base_input(None)).unwrap();
        let poc = &capsule["model_attestation"]["compute_attestation"]["x-mesh-poc-v1"];

        // Truthful name: NOT model_package_digest (weights), it's a name hash.
        assert_eq!(poc["model_name_digest"], "d".repeat(64));
        assert!(
            poc.get("model_package_digest").is_none(),
            "the overclaiming name must be gone entirely"
        );

        let prov = provenance(&capsule);
        assert_eq!(prov["served_by_node_id"], "node-under-test");
        assert_eq!(prov["requesting_party"], "client-under-test");
        assert_eq!(prov["exchange_id"], "exch-under-test");
        // Host does not expose quantization -> explicit "unknown", not invented.
        assert_eq!(prov["quantization"], "unknown");
        // Host does not expose hardware -> all null, not invented.
        assert!(prov["hardware"]["gpu"].is_null());
        assert!(prov["hardware"]["vram_bytes"].is_null());
        assert!(prov["hardware"]["device"].is_null());
        // Usage IS real when the response carried it.
        assert_eq!(prov["usage"]["prompt_tokens"], 11);
        assert_eq!(prov["usage"]["completion_tokens"], 22);
        assert_eq!(prov["usage"]["total_tokens"], 33);
    }

    /// Mutating ANY provenance field changes `capsule_id` — the record is
    /// content-addressed over its provenance, so an attester cannot swap the
    /// served node, exchange id, or token counts without breaking the digest.
    #[test]
    fn mutating_a_provenance_field_changes_capsule_id() {
        let baseline = seal(&base_input(None)).unwrap();
        let baseline_id = baseline["capsule_id"].as_str().unwrap().to_string();

        // (1) served_by_node_id
        let mut input = base_input(None);
        input.mesh_poc.serving_provenance.served_by_node_id = "other-node".to_string();
        assert_ne!(seal(&input).unwrap()["capsule_id"], baseline_id.as_str());

        // (2) exchange_id
        let mut input = base_input(None);
        input.mesh_poc.serving_provenance.exchange_id = "other-exch".to_string();
        assert_ne!(seal(&input).unwrap()["capsule_id"], baseline_id.as_str());

        // (3) quantization
        let mut input = base_input(None);
        input.mesh_poc.serving_provenance.quantization = "Q4_K_M".to_string();
        assert_ne!(seal(&input).unwrap()["capsule_id"], baseline_id.as_str());

        // (4) usage token counts
        let mut input = base_input(None);
        input.mesh_poc.serving_provenance.usage = Some(TokenUsage {
            prompt_tokens: 999,
            completion_tokens: 1,
            total_tokens: 1000,
        });
        assert_ne!(seal(&input).unwrap()["capsule_id"], baseline_id.as_str());

        // (5) model_name_digest
        let mut input = base_input(None);
        input.mesh_poc.model_name_digest = "e".repeat(64);
        assert_ne!(seal(&input).unwrap()["capsule_id"], baseline_id.as_str());
    }

    #[test]
    fn standalone_capsule_has_no_chain_block_and_standalone_ledger_mode() {
        let capsule = seal(&base_input(None)).unwrap();
        assert!(capsule.get("chain").is_none());
        assert_eq!(capsule["assurance"]["ledger_mode"], "standalone");
    }

    #[test]
    fn chained_capsule_carries_chain_block_and_chained_ledger_mode() {
        let parent = "f".repeat(64);
        let input = base_input(Some(ChainLink {
            parent_capsule_id: parent.clone(),
            relation: "follows".to_string(),
        }));
        let capsule = seal(&input).unwrap();
        assert_eq!(capsule["chain"]["parent_capsule_id"], parent);
        assert_eq!(capsule["chain"]["relation"], "follows");
        assert_eq!(capsule["assurance"]["ledger_mode"], "chained");
    }

    #[test]
    fn capsule_id_is_independent_of_the_chain_blocks_content() {
        // §5.1 / jcs::CHAIN_LINKAGE_FIELDS excludes `chain` itself from the
        // digest -- so among capsules that are ALREADY chained (same
        // ledger_mode), varying parent_capsule_id/relation must not perturb
        // capsule_id. (ledger_mode itself IS digest-bearing -- see the
        // standalone-vs-chained test above, where ledger_mode "standalone"
        // vs "chained" correctly DOES change capsule_id; that's a different
        // field, not the chain block's content.)
        let chained_a = seal(&base_input(Some(ChainLink {
            parent_capsule_id: "f".repeat(64),
            relation: "follows".to_string(),
        })))
        .unwrap();
        let chained_b = seal(&base_input(Some(ChainLink {
            parent_capsule_id: "0".repeat(64),
            relation: "confirms".to_string(),
        })))
        .unwrap();
        assert_eq!(chained_a["capsule_id"], chained_b["capsule_id"]);
        // And the chain block itself is still exactly what was supplied,
        // even though it didn't affect the digest.
        assert_eq!(chained_a["chain"]["parent_capsule_id"], "f".repeat(64));
        assert_eq!(chained_b["chain"]["parent_capsule_id"], "0".repeat(64));
    }
}
