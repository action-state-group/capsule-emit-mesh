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
/// `mesh-llm/…/plugin/openai_exchange.rs` on the `mesh1331-lifecycle-hooks` +
/// `feat/serving-provenance` branch and `openai-frontend`'s
/// `ChatCompletionResponse`):
///
/// - `model` (the served model NAME) — already in `model_attestation.model_id`
/// - `usage` (prompt/completion/total tokens) — in the response body
/// - `exchange_id` / a per-exchange correlation id, `nonce`, `nonce_source`,
///   `capsule_id` marker, `status`, `dispatch_path` — on the lifecycle event
/// - the emitting node's own id — this plugin's `node_id`
/// - **NEW (host `serving_provenance` block):** quantization, architecture,
///   context length, parameter size, layer count, model identity hash /
///   canonical ref / revision, serving GPU, VRAM bytes, SoC flag, and the
///   serving node id + hostname — read straight from the host's terminal
///   event when it carries them.
///
/// Fields the host STILL does not expose stay honest defaults
/// (`"unknown"`/`null`), and any host field this plugin has not yet observed
/// for the served model likewise stays at its default — never fabricated:
///
/// - `hardware_device` — the host carries an `is_soc` flag, not a cpu/cuda/
///   metal device enum, so this stays `null` unless a future event adds one.
/// - a serving-peer node id DISTINCT from the requester — in the single-node
///   PoC the host's `served_by_node_id` and the requester are the same node.
#[derive(Clone)]
pub struct ServingProvenance {
    /// The node that actually served the inference. Prefer the host event's
    /// `served_by_node_id` when observed; otherwise the emitting plugin's own
    /// `node_id` (single-node PoC).
    pub served_by_node_id: String,
    /// The requesting party / client identity for this exchange. `"unknown"`
    /// when the caller supplied no identity beyond the (optional) client nonce.
    pub requesting_party: String,
    /// Stable per-exchange correlation id (the host's `exchange_id` /
    /// response `id` / `x-request-id` lineage), so this record can be tied back
    /// to the host's own terminal-event log for the same exchange.
    pub exchange_id: String,
    /// Model QUANTIZATION (e.g. "Q4_K_M"), read from the host's serving
    /// provenance when present; `"unknown"` when the host reported none
    /// (unquantized weights, or a host predating the block) — never guessed.
    pub quantization: String,
    /// Serving hardware, populated from the host's serving-provenance block
    /// when it carries them; `null` otherwise. `hardware_device` stays `null`
    /// (host carries `is_soc`, not a device enum) — never fabricated.
    pub hardware_gpu: Option<String>,
    pub hardware_vram_bytes: Option<u64>,
    pub hardware_device: Option<String>,
    /// Whether the serving host is a unified-memory SoC, from the host event.
    pub hardware_is_soc: Option<bool>,
    /// Serving host name, from the host event.
    pub hostname: Option<String>,
    /// Model IDENTITY / fidelity from the host serving-provenance block. Each
    /// is `None` when the host did not report it — never fabricated.
    pub architecture: Option<String>,
    pub context_length: Option<u32>,
    pub parameter_size: Option<String>,
    pub layer_count: Option<u32>,
    /// Content-addressed identity hash of the served model artifact (a digest
    /// of the model identity, NOT of the model *name* string). `None` when the
    /// host did not resolve one.
    pub model_identity_hash: Option<String>,
    pub model_canonical_ref: Option<String>,
    pub model_revision: Option<String>,
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
            "hostname": self.hostname,
            // Quantization: real value from the host event, or "unknown".
            "quantization": self.quantization,
            // Model identity / fidelity from the host serving-provenance block.
            "model": {
                "architecture": self.architecture,
                "context_length": self.context_length,
                "parameter_size": self.parameter_size,
                "layer_count": self.layer_count,
                "identity_hash": self.model_identity_hash,
                "canonical_ref": self.model_canonical_ref,
                "revision": self.model_revision,
            },
            // Serving hardware from the host serving-provenance block.
            "hardware": {
                "gpu": self.hardware_gpu,
                "vram_bytes": self.hardware_vram_bytes,
                // Host carries is_soc, not a cpu/cuda/metal device enum.
                "device": self.hardware_device,
                "is_soc": self.hardware_is_soc,
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
    /// The runtime/binary attestation rung (task B3): a signed, `self_measured`
    /// reference to the serving binary the node actually runs, or `None` when
    /// the binary could not be measured (graceful degradation — the
    /// `binary_attestation` evidence slot is then recorded empty, never
    /// fabricated). See [`crate::runtime_attest`] for the honesty grade: this is
    /// SELF-measured (the node hashed its own binary) and is only trustworthy up
    /// to an OS/TEE that independently measures it.
    pub binary_attestation: Option<crate::runtime_attest::BinaryAttestation>,
    /// The `tee_measured` rung (rung 3c): a parsed, hardware-signed TDX quote
    /// binding MRTD/RTMR[0..3] to this exchange, or `None` on a host without
    /// TDX (graceful degradation, same contract as `binary_attestation` —
    /// the `tee_attestation` evidence slot is then recorded empty, never
    /// fabricated). See [`crate::tee_attest`]/[`crate::tee_verify`]: this is
    /// the strongest measurement grade this codebase names, produced by the
    /// TDX module beneath the guest OS rather than the process itself.
    pub tee_attestation: Option<crate::tee_attest::TeeAttestation>,
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
            // Typed reference fields, present-but-empty (issue #1233 step 4,
            // statistical fingerprint, is future work that upgrades this slot
            // without changing the record shape).
            //
            // `binary_attestation` (task B3) is the runtime/binary-attestation
            // rung: a SIGNED, `self_measured` reference to the serving binary the
            // node runs. When the binary could not be measured (unresolvable
            // path / unreadable file) the slot degrades to the same empty shape
            // as the other future slots — recorded ABSENT, never fabricated.
            //
            // `tee_attestation` (rung 3c) is the `tee_measured` rung: a parsed
            // TDX quote binding MRTD/RTMR[0..3] to this exchange. Absent on any
            // host without TDX hardware (the overwhelming majority today) —
            // recorded empty, never fabricated. See `crate::tee_attest`.
            "evidence_refs": {
                "statistical_fingerprint": {"type": "statistical_fingerprint", "digest": null, "context": null},
                "tee_attestation": match &self.tee_attestation {
                    Some(att) => att.to_value(),
                    None => json!({
                        "type": "tee_attestation",
                        "measurement_class": null,
                        "digest": null,
                        "context": "no TEE quote measured (no TDX hardware on this host, or the producer leg has not run here); recorded absent, never fabricated",
                    }),
                },
                "binary_attestation": match &self.binary_attestation {
                    Some(att) => att.to_value(),
                    // Honest empty slot: no binary was measured, so no
                    // measurement is claimed. `measurement_class` stays null so a
                    // reader never mistakes an unmeasured node for a self_measured
                    // one.
                    None => json!({
                        "type": "binary_attestation",
                        "measurement_class": null,
                        "digest": null,
                        "context": "binary not measured (path unresolvable or file unreadable); recorded absent, never fabricated",
                    }),
                },
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
    /// OPTIONAL labeled sub-digest over the flattened `tool_calls` the model
    /// emitted for this exchange, mirroring the Python reference
    /// `capsule_ledger/conversation/exchange.py`'s `digest_conversation_exchange`
    /// (`tool_calls_digest = json_digest(tool_calls) if tool_calls else None`).
    /// `None` — and then ABSENT from the sealed capsule, never a fabricated
    /// digest over `[]` — when the model emitted no tool call, so a reader can
    /// never misread the record as asserting "zero tool calls". Rides inside
    /// `model_attestation.compute_attestation` alongside `agent_output_digest`.
    pub tool_calls_digest: Option<String>,
    /// OPTIONAL labeled sub-digest over the model's `reasoning_content` chunk(s)
    /// (same reference/shape as `tool_calls_digest`). `None` — and ABSENT from
    /// the capsule — when the model surfaced no reasoning (the honest null for a
    /// non-reasoning model like Llama-3.2), never fabricated.
    pub reasoning_digest: Option<String>,
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
    // compute_attestation carries the mandatory input/output digests plus the
    // OPTIONAL labeled sub-digests `tool_calls_digest`/`reasoning_digest` —
    // inserted ONLY when present, exactly as the Python reference
    // `digest_conversation_exchange`/`build_conversation_exchange_capsule`
    // does (absent, never a fabricated digest, when the model had none). Placing
    // them beside `agent_output_digest` makes tier-2 fold-scoped disclosure
    // possible: a holder can later disclose just the tool-call bytes without the
    // prompt/reasoning, because each is committed under its own label.
    let mut compute_attestation = Map::new();
    compute_attestation.insert("agent_input_digest".into(), json!(input.agent_input_digest));
    compute_attestation.insert(
        "agent_output_digest".into(),
        json!(input.agent_output_digest),
    );
    if let Some(tcd) = &input.tool_calls_digest {
        compute_attestation.insert("tool_calls_digest".into(), json!(tcd));
    }
    if let Some(rd) = &input.reasoning_digest {
        compute_attestation.insert("reasoning_digest".into(), json!(rd));
    }
    compute_attestation.insert("runtime".into(), json!(input.runtime));
    compute_attestation.insert("x-mesh-poc-v1".into(), input.mesh_poc.to_value());
    body.insert(
        "model_attestation".into(),
        json!({
            "model_id": input.model_id,
            "provider": input.provider,
            "compute_attestation": Value::Object(compute_attestation),
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
            tool_calls_digest: None,
            reasoning_digest: None,
            runtime: "runtime".to_string(),
            mesh_poc: MeshPocV1 {
                client_nonce: "c".repeat(32),
                client_nonce_source: "client_supplied".to_string(),
                model_name_digest: "d".repeat(64),
                serving_provenance: ServingProvenance {
                    served_by_node_id: "node-under-test".to_string(),
                    requesting_party: "client-under-test".to_string(),
                    exchange_id: "exch-under-test".to_string(),
                    quantization: "Q4_K_M".to_string(),
                    hardware_gpu: Some("Apple M3 Max".to_string()),
                    hardware_vram_bytes: Some(38_654_705_664),
                    hardware_device: None,
                    hardware_is_soc: Some(true),
                    hostname: Some("host-under-test".to_string()),
                    architecture: Some("llama".to_string()),
                    context_length: Some(8192),
                    parameter_size: Some("7B".to_string()),
                    layer_count: Some(32),
                    model_identity_hash: Some("a".repeat(64)),
                    model_canonical_ref: Some("repo@rev/model.gguf".to_string()),
                    model_revision: Some("rev".to_string()),
                    usage: Some(TokenUsage {
                        prompt_tokens: 11,
                        completion_tokens: 22,
                        total_tokens: 33,
                    }),
                },
                generation_parameters,
                latency_ms: "1.0".to_string(),
                binary_attestation: None,
                tee_attestation: None,
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
        assert_eq!(prov["hostname"], "host-under-test");
        // Quantization from the host serving-provenance block (real value).
        assert_eq!(prov["quantization"], "Q4_K_M");
        // Model identity / fidelity from the host serving-provenance block.
        assert_eq!(prov["model"]["architecture"], "llama");
        assert_eq!(prov["model"]["context_length"], 8192);
        assert_eq!(prov["model"]["parameter_size"], "7B");
        assert_eq!(prov["model"]["layer_count"], 32);
        assert_eq!(prov["model"]["identity_hash"], "a".repeat(64));
        assert_eq!(prov["model"]["canonical_ref"], "repo@rev/model.gguf");
        assert_eq!(prov["model"]["revision"], "rev");
        // Hardware from the host serving-provenance block (real values).
        assert_eq!(prov["hardware"]["gpu"], "Apple M3 Max");
        assert_eq!(prov["hardware"]["vram_bytes"], 38_654_705_664u64);
        assert_eq!(prov["hardware"]["is_soc"], true);
        // Host carries is_soc, not a device enum -> device stays null.
        assert!(prov["hardware"]["device"].is_null());
        // Usage IS real when the response carried it.
        assert_eq!(prov["usage"]["prompt_tokens"], 11);
        assert_eq!(prov["usage"]["completion_tokens"], 22);
        assert_eq!(prov["usage"]["total_tokens"], 33);
    }

    /// The OPTIONAL `tool_calls_digest`/`reasoning_digest` sub-digests ride
    /// inside `compute_attestation` beside `agent_output_digest` when present,
    /// mirroring the Python reference shape. This is the slot a real
    /// tool_calls_digest lands in.
    #[test]
    fn capsule_carries_optional_tool_calls_and_reasoning_digests_when_present() {
        let mut input = base_input(None);
        input.tool_calls_digest = Some("f".repeat(64));
        input.reasoning_digest = Some("e".repeat(64));
        let capsule = seal(&input).unwrap();
        let ca = &capsule["model_attestation"]["compute_attestation"];
        assert_eq!(ca["tool_calls_digest"], "f".repeat(64));
        assert_eq!(ca["reasoning_digest"], "e".repeat(64));
        // The mandatory digests are still present alongside them.
        assert_eq!(ca["agent_output_digest"], "b".repeat(64));
    }

    /// ABSENT, not null: when the model had no tool calls / no reasoning, the
    /// keys are omitted entirely from the sealed capsule — never a fabricated
    /// digest over an empty list — exactly as the Python reference
    /// `build_conversation_exchange_capsule` omits them.
    #[test]
    fn capsule_omits_optional_sub_digests_when_absent() {
        let capsule = seal(&base_input(None)).unwrap();
        let ca = &capsule["model_attestation"]["compute_attestation"];
        assert!(
            ca.get("tool_calls_digest").is_none(),
            "an absent tool_calls_digest must be omitted, not null"
        );
        assert!(
            ca.get("reasoning_digest").is_none(),
            "an absent reasoning_digest must be omitted, not null"
        );
    }

    /// The sub-digests are digest-bound: setting a real `tool_calls_digest`
    /// changes `capsule_id`, so an attester cannot swap the tool calls out of a
    /// sealed record without breaking the content address.
    #[test]
    fn setting_tool_calls_digest_changes_capsule_id() {
        let baseline = seal(&base_input(None)).unwrap();
        let baseline_id = baseline["capsule_id"].as_str().unwrap().to_string();
        let mut input = base_input(None);
        input.tool_calls_digest = Some("f".repeat(64));
        assert_ne!(seal(&input).unwrap()["capsule_id"], baseline_id.as_str());
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

        // (3) quantization (baseline is "Q4_K_M"; mutate to a different quant)
        let mut input = base_input(None);
        input.mesh_poc.serving_provenance.quantization = "Q8_0".to_string();
        assert_ne!(seal(&input).unwrap()["capsule_id"], baseline_id.as_str());

        // (3b) a model-fidelity field (architecture) is also digest-bound.
        let mut input = base_input(None);
        input.mesh_poc.serving_provenance.architecture = Some("mistral".to_string());
        assert_ne!(seal(&input).unwrap()["capsule_id"], baseline_id.as_str());

        // (3c) a hardware field (gpu) is also digest-bound.
        let mut input = base_input(None);
        input.mesh_poc.serving_provenance.hardware_gpu = Some("NVIDIA H100".to_string());
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
