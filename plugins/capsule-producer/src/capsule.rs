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
    /// SHA-256 of the served GGUF's file BYTES, from the host's load-time
    /// hash of the file it actually opened for serving. A different fact
    /// from `model_identity_hash` (a hash of a reference STRING, or absent
    /// for a bare local path) -- this never replaces it. `None` when the
    /// host has not resolved one (unreadable file, or no load-time hash
    /// computed yet for this model).
    pub weights_digest: Option<String>,
    pub model_canonical_ref: Option<String>,
    pub model_revision: Option<String>,
    /// Token accounting from the response `usage`, or `None` if absent.
    pub usage: Option<TokenUsage>,
    /// This record's position in the monotone per-`(self, counterparty)`
    /// sequence (history proposal §1 -- continuity is bilateral only), from
    /// [`crate::sequence::SequenceCounterStore`]. `self` is this node
    /// (`served_by_node_id`); `counterparty` is `requesting_party`.
    pub seq: u64,
    /// The pair's previous `seq`, or `None` for this pair's first-ever
    /// record. A verifier walking the ledger checks `prev_seq` against the
    /// prior record's `seq` for the same pair -- see
    /// [`crate::sequence::verify_pair_continuity`].
    pub prev_seq: Option<u64>,
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
                "weights_digest": self.weights_digest,
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
            "seq": self.seq,
            "prev_seq": self.prev_seq,
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

/// The registered label for mesh-llm's own request-body digest, stated AS
/// DATA: the exact byte source is the HTTP request body as mesh-llm's host
/// runtime transmitted it (before any canonicalization on our side), the
/// hash is SHA-256, and the representation is unprefixed lowercase hex —
/// mesh-llm's own scheme, as mesh-llm defines it, never re-derived here.
pub const MESH_LLM_REQUEST_BODY_SHA256_V1: &str = "mesh-llm/request-body-sha256/v1";

/// A registered `host_binding.construction` label. Each entry states, AS
/// DATA, the exact byte source, hash, and representation the label pins —
/// this module does not normalize, re-encode, or re-derive those bytes. The
/// closed set exists so [`validate_host_binding`] can reject an unregistered
/// or missing label rather than accept any string.
pub const REGISTERED_HOST_BINDING_CONSTRUCTIONS: &[&str] = &[MESH_LLM_REQUEST_BODY_SHA256_V1];

/// The registered `host_binding.purpose` label for joining this record into
/// mesh-llm's own operational log.
pub const HOST_LOG_JOIN: &str = "host-log-join";

/// A registered `host_binding.purpose` label (mirrors the entry's
/// purpose-label list convention). `host-log-join` is the first member.
pub const REGISTERED_HOST_BINDING_PURPOSES: &[&str] = &[HOST_LOG_JOIN];

/// Reverse-direction composition binding (host-native digest) — the
/// application of the AAC Composition WHAT-slot "Additional composition
/// bindings" rule to this record: mesh-llm's OWN digest for the same
/// exchange, carried under mesh-llm's OWN construction, so the record joins
/// the host platform's operational log without either side re-canonicalizing
/// the other's bytes.
///
/// INDEPENDENCE RULE (normative): a verifier MUST NOT infer equality,
/// derivation, or transitive coverage between `host_binding.digest` and any
/// other binding on the record (including `agent_input_digest`) merely
/// because they cover the same exchange, share a hash algorithm, or appear
/// in the same signed payload. Two bindings on one record are two
/// independent, co-signed claims — byte-equality between them is NOT
/// required, NOT implied, and MUST NOT be assumed by tooling. See
/// [`validate_host_binding`], which performs ONLY structural checks and
/// never compares `digest` against any other field, and the `mod tests`
/// `equality_inference_mutant_*` tests, which demonstrate why.
#[derive(Clone)]
pub struct HostBinding {
    /// The host's own digest for this exchange, lowercase hex, as mesh-llm
    /// computed it — never re-derived here.
    pub digest: String,
    /// REQUIRED registered context label naming mesh-llm's own construction
    /// (what bytes, what hash, stated as data — see
    /// `REGISTERED_HOST_BINDING_CONSTRUCTIONS`), never a code-line citation.
    pub construction: String,
    /// A label from `REGISTERED_HOST_BINDING_PURPOSES`.
    pub purpose: String,
}

impl HostBinding {
    fn to_value(&self) -> Value {
        json!({
            "digest": self.digest,
            "construction": self.construction,
            "purpose": self.purpose,
        })
    }
}

/// Structural validation ONLY: presence and shape of `host_binding`. This
/// function intentionally does NOT read or compare against
/// `agent_input_digest` (or anything else on the record) — see the
/// INDEPENDENCE RULE on [`HostBinding`]. It exists so a verifier can reject a
/// malformed group (missing/unregistered `construction`, a `null` group)
/// without ever inferring equality between two independent bindings.
pub fn validate_host_binding(capsule: &Value) -> Result<(), String> {
    let compute_attestation = capsule
        .get("model_attestation")
        .and_then(|m| m.get("compute_attestation"));
    let Some(hb) = compute_attestation.and_then(|ca| ca.get("host_binding")) else {
        // Absent key entirely -- OPTIONAL group, nothing to check.
        return Ok(());
    };
    if hb.is_null() {
        return Err("host_binding present but null -- must be absent, never null".to_string());
    }
    let obj = hb
        .as_object()
        .ok_or_else(|| "host_binding is not an object".to_string())?;
    let digest = obj
        .get("digest")
        .and_then(Value::as_str)
        .ok_or_else(|| "host_binding.digest missing or not a string".to_string())?;
    if digest.len() != 64
        || !digest
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Err("host_binding.digest is not lowercase-hex-64".to_string());
    }
    let construction = obj
        .get("construction")
        .and_then(Value::as_str)
        .ok_or_else(|| "host_binding.construction missing or not a string".to_string())?;
    if !REGISTERED_HOST_BINDING_CONSTRUCTIONS.contains(&construction) {
        return Err(format!(
            "host_binding.construction {construction:?} is not a registered label"
        ));
    }
    let purpose = obj
        .get("purpose")
        .and_then(Value::as_str)
        .ok_or_else(|| "host_binding.purpose missing or not a string".to_string())?;
    if !REGISTERED_HOST_BINDING_PURPOSES.contains(&purpose) {
        return Err(format!(
            "host_binding.purpose {purpose:?} is not a registered label"
        ));
    }
    Ok(())
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
    /// OPTIONAL reverse-direction composition binding — mesh-llm's own digest
    /// for this exchange, under its own construction. `None` — and ABSENT
    /// from the capsule, never null — when the host exposed no digest for
    /// this exchange. See [`HostBinding`] for the independence rule.
    pub host_binding: Option<HostBinding>,
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
    // host_binding: OPTIONAL reverse-direction composition binding, inserted
    // ONLY when present -- never null. See `HostBinding`'s INDEPENDENCE RULE:
    // this is a second, independent claim, not a re-derivation of
    // `agent_input_digest`.
    if let Some(hb) = &input.host_binding {
        compute_attestation.insert("host_binding".into(), hb.to_value());
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
            host_binding: None,
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
                    weights_digest: Some("9".repeat(64)),
                    model_canonical_ref: Some("repo@rev/model.gguf".to_string()),
                    model_revision: Some("rev".to_string()),
                    usage: Some(TokenUsage {
                        prompt_tokens: 11,
                        completion_tokens: 22,
                        total_tokens: 33,
                    }),
                    seq: 1,
                    prev_seq: None,
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
        // The bytes-hash rides alongside the name-hash as a distinct fact.
        assert_eq!(prov["model"]["weights_digest"], "9".repeat(64));
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

        // (3d) the weights digest is also digest-bound -- a quant swap under
        // the same model name records as a changed capsule (it does not
        // prevent the swap; it makes it a signed, non-repudiable fact).
        let mut input = base_input(None);
        input.mesh_poc.serving_provenance.weights_digest = Some("8".repeat(64));
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

    // =======================================================================
    // host_binding — reverse-direction composition binding
    // =======================================================================

    /// Positive vector: a `host_binding` group carries mesh-llm's own digest
    /// under its own construction, structurally valid per
    /// `validate_host_binding`, and digest-bound into `capsule_id`.
    #[test]
    fn host_binding_present_is_carried_and_valid() {
        let mut input = base_input(None);
        input.host_binding = Some(HostBinding {
            digest: "a6329c5ebb66562f38a8136a8d8511b6aeed166e4c7d889b9133ac96fc49a9d5"
                .to_string(),
            construction: MESH_LLM_REQUEST_BODY_SHA256_V1.to_string(),
            purpose: HOST_LOG_JOIN.to_string(),
        });
        let capsule = seal(&input).unwrap();
        let hb = &capsule["model_attestation"]["compute_attestation"]["host_binding"];
        assert_eq!(
            hb["digest"],
            "a6329c5ebb66562f38a8136a8d8511b6aeed166e4c7d889b9133ac96fc49a9d5"
        );
        assert_eq!(hb["construction"], MESH_LLM_REQUEST_BODY_SHA256_V1);
        assert_eq!(hb["purpose"], HOST_LOG_JOIN);
        assert!(validate_host_binding(&capsule).is_ok());

        // digest-bound: a different host digest changes capsule_id.
        let baseline_id = capsule["capsule_id"].as_str().unwrap().to_string();
        let mut other = base_input(None);
        other.host_binding = Some(HostBinding {
            digest: "0".repeat(64),
            construction: MESH_LLM_REQUEST_BODY_SHA256_V1.to_string(),
            purpose: HOST_LOG_JOIN.to_string(),
        });
        assert_ne!(seal(&other).unwrap()["capsule_id"], baseline_id.as_str());
    }

    /// Absence rule: when no host digest exists, the key is OMITTED entirely
    /// — never present as `null`.
    #[test]
    fn host_binding_absent_when_not_supplied() {
        let capsule = seal(&base_input(None)).unwrap();
        let ca = &capsule["model_attestation"]["compute_attestation"];
        assert!(
            ca.get("host_binding").is_none(),
            "an absent host_binding must be omitted, not null"
        );
        assert!(validate_host_binding(&capsule).is_ok());
    }

    /// MUST-FAIL (a): `construction` missing or unregistered.
    #[test]
    fn must_fail_construction_missing_or_unregistered() {
        let mut capsule = seal(&base_input(None)).unwrap();
        // (a1) construction missing entirely.
        capsule["model_attestation"]["compute_attestation"]["host_binding"] = json!({
            "digest": "a".repeat(64),
            "purpose": HOST_LOG_JOIN,
        });
        assert!(validate_host_binding(&capsule).is_err());

        // (a2) construction present but not a registered label.
        capsule["model_attestation"]["compute_attestation"]["host_binding"] = json!({
            "digest": "a".repeat(64),
            "construction": "some-unregistered-scheme/v1",
            "purpose": HOST_LOG_JOIN,
        });
        assert!(validate_host_binding(&capsule).is_err());
    }

    /// MUST-FAIL (b): a `null` group — the absence rule requires the key be
    /// OMITTED, never carried as `null`.
    #[test]
    fn must_fail_null_group() {
        let mut capsule = seal(&base_input(None)).unwrap();
        capsule["model_attestation"]["compute_attestation"]["host_binding"] = Value::Null;
        assert!(validate_host_binding(&capsule).is_err());
    }

    /// MUST-FAIL (c) — THE ACCEPTANCE CENTERPIECE: the equality-inference
    /// mutant. `host_binding.digest` and `agent_input_digest` are two
    /// independent, co-signed claims (the INDEPENDENCE RULE on
    /// [`HostBinding`]) — a record where they legitimately DIFFER (mesh-llm's
    /// format drifting from ours) is still a perfectly valid record.
    ///
    /// `validate_host_binding` (the real structural check) agrees: it never
    /// reads `agent_input_digest`, so a divergent-but-well-formed
    /// `host_binding` still passes.
    ///
    /// The MUTANT below is a verifier that additionally infers equality
    /// between the two bindings — exactly the inference the independence
    /// rule prohibits. Run against the SAME divergent-but-valid record, the
    /// mutant WRONGLY rejects it. That the mutant fails red here is the
    /// point: it demonstrates precisely the false rejection the rule exists
    /// to prevent, and pins that this crate's real verifier contains no such
    /// inference.
    #[test]
    fn equality_inference_mutant_wrongly_rejects_legitimate_format_drift() {
        let mut input = base_input(None);
        input.agent_input_digest = "1".repeat(64); // our construction's value
        input.host_binding = Some(HostBinding {
            digest: "2".repeat(64), // mesh-llm's construction's value -- DIFFERENT
            construction: MESH_LLM_REQUEST_BODY_SHA256_V1.to_string(),
            purpose: HOST_LOG_JOIN.to_string(),
        });
        let capsule = seal(&input).unwrap();

        // The REAL verifier: independence respected, passes.
        assert!(
            validate_host_binding(&capsule).is_ok(),
            "the real validator must not infer equality and must accept divergent bindings"
        );

        // The MUTANT verifier: infers equality, wrongly fails.
        assert!(
            equality_inference_mutant(&capsule).is_err(),
            "MUTANT FAILS RED as expected: inferring equality between two \
             independent bindings wrongly rejects a legitimate record"
        );
    }

    /// The equality-inference mutant also wrongly rejects on the very
    /// PLUMBING every other test in this module uses (`host_binding` absent):
    /// with no `host_binding` present there is nothing to compare, so both
    /// the real validator and this mutant agree — Ok. Included so the mutant
    /// is not vacuously "always Err" and only fails on the case that matters.
    #[test]
    fn equality_inference_mutant_agrees_when_host_binding_absent() {
        let capsule = seal(&base_input(None)).unwrap();
        assert!(validate_host_binding(&capsule).is_ok());
        assert!(equality_inference_mutant(&capsule).is_ok());
    }

    /// A MUTANT verifier, deliberately wrong: asserts record validity BECAUSE
    /// `host_binding.digest == agent_input_digest`. This function exists ONLY
    /// to be exercised by the tests above — production code (`seal`,
    /// `validate_host_binding`) contains no such comparison anywhere.
    fn equality_inference_mutant(capsule: &Value) -> Result<(), String> {
        let ca = capsule
            .get("model_attestation")
            .and_then(|m| m.get("compute_attestation"))
            .ok_or_else(|| "missing compute_attestation".to_string())?;
        let Some(hb) = ca.get("host_binding").filter(|v| !v.is_null()) else {
            return Ok(()); // nothing to (wrongly) compare
        };
        let hb_digest = hb
            .get("digest")
            .and_then(Value::as_str)
            .ok_or_else(|| "host_binding.digest missing".to_string())?;
        let agent_input_digest = ca
            .get("agent_input_digest")
            .and_then(Value::as_str)
            .ok_or_else(|| "agent_input_digest missing".to_string())?;
        if hb_digest != agent_input_digest {
            return Err(format!(
                "MUTANT: host_binding.digest {hb_digest:?} != agent_input_digest \
                 {agent_input_digest:?} -- treated as invalid (WRONG: these are \
                 two independent bindings, not required to match)"
            ));
        }
        Ok(())
    }
}
