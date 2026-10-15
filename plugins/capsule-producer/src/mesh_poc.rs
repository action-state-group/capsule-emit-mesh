//! The Mesh-specific members of a capsule this plugin seals: the `x-mesh-poc-v1`
//! extension and the model/hardware/invocation members derived from it, plus
//! mesh-llm's registered `host_binding` labels.
//!
//! Sealing itself is `capsule_emit::capsule::seal`: a caller builds a
//! `capsule_emit::capsule::CapsuleInput` and passes [`extensions`] as its
//! `compute_attestation_extensions`. capsule-emit commits those members into
//! `capsule_id` in order and never interprets them.

use capsule_emit::capsule::CORE_COMPUTE_ATTESTATION_MEMBERS;
use serde_json::{json, Map, Value};

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
    /// The raw `dispatch_path` wire value this record was derived from (e.g.
    /// `"remote_mesh"`, `"typed_frontend"`, `"raw_proxy"`, `"unknown"`), or
    /// `None` on a path that never received one (this plugin's own directly
    /// admitted `/v1` exchanges, which have no host envelope at all). Carried
    /// alongside `MeshPocV1::role` (a sibling, top-level field on the
    /// enclosing block -- see its doc comment for why it lives there and not
    /// here) even when they agree -- on a `role: "conflict"` this is one of
    /// the two raw facts a reader needs to see why, not just a resolved label.
    pub dispatch_path: Option<String>,
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
    /// [`capsule_emit::sequence::SequenceCounterStore`]. `self` is this node
    /// (`served_by_node_id`); `counterparty` is `requesting_party`.
    pub seq: u64,
    /// The pair's previous `seq`, or `None` for this pair's first-ever
    /// record. A verifier walking the ledger checks `prev_seq` against the
    /// prior record's `seq` for the same pair -- see
    /// [`capsule_emit::sequence::verify_pair_continuity`].
    pub prev_seq: Option<u64>,
    /// On a `role: "requested"` record: the capsule id the PEER asserted for
    /// its own (served-side) half of this exchange -- the lookup key an
    /// evidence-door fetch dereferences to populate the two-sided ledger's
    /// "theirs" column. Forwarded verbatim off the host's `RemoteMesh`
    /// terminal envelope (`mesh-llm-host-runtime`'s
    /// `CapsuleIdProvenance::PeerAsserted`) -- an unauthenticated,
    /// relay-injectable value observed on the peer's raw response header
    /// while ROUTING, never itself verified or countersigned here. `None`
    /// on every `role: "served"` record (there is no peer half to name) and
    /// on a `requested` record where no value was observed.
    pub peer_capsule_id: Option<String>,
    /// How `peer_capsule_id` was obtained -- the wire value of the host's
    /// `CapsuleIdProvenance` (`"peer_asserted"` today; `"unknown"` for a
    /// value this mirror predates). `None` exactly when `peer_capsule_id`
    /// is `None`. Graded self-attested/peer-asserted, never promoted to a
    /// verified or countersigned claim by this field's mere presence.
    pub peer_capsule_id_provenance: Option<String>,
    /// The id shared by BOTH halves of an ambient twin comparison, forwarded
    /// verbatim from the terminal `openai.exchange.v1` envelope's own
    /// `twin_bracket_id` (host-minted; this plugin never mints or derives
    /// one). `None` -- and then ABSENT from the sealed capsule, never a
    /// fabricated default -- on every exchange the envelope reports as not
    /// twinned (the overwhelming majority). Both rows of a real twin carry
    /// the identical string because both plugin instances forward the same
    /// host-minted value off their own terminal envelope for that exchange.
    pub twin_bracket_id: Option<String>,
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
        let mut value = json!({
            "served_by_node_id": self.served_by_node_id,
            "dispatch_path": self.dispatch_path,
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
            "peer_capsule_id": self.peer_capsule_id,
            "peer_capsule_id_provenance": self.peer_capsule_id_provenance,
        });
        // twin_bracket_id: OMITTED entirely when the envelope carried none --
        // never a null placeholder -- so an untwinned row (the overwhelming
        // majority) never reads as a half-bracket.
        if let Some(twin_bracket_id) = &self.twin_bracket_id {
            value
                .as_object_mut()
                .expect("serving_provenance value is always a JSON object")
                .insert("twin_bracket_id".into(), json!(twin_bracket_id));
        }
        value
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
    /// Which half of this exchange this record is: `"requested"` (this node
    /// routed the exchange to a peer, never served it), `"served"` (this node
    /// served it), `"conflict"` (the `dispatch_path`-derived expectation and
    /// the `served_by_node_id`-vs-self consistency check disagree -- both raw
    /// signals still ride alongside in `serving_provenance` so a reader never
    /// has to take this label's word for it), or `"unknown"` (an
    /// unrecognized `dispatch_path`). 2026-09-06 role ruling.
    /// `capsule_mesh_view.label_role()` reads this exact top-level field
    /// FIRST, as the authoritative signal -- mirrors `capsule_sidecar.py`'s
    /// own top-level `x-mesh-poc-v1.role` field exactly, and deliberately
    /// lives HERE, a sibling of `serving_provenance`, not nested inside it:
    /// `serving_provenance` there already has its own `role` key in the
    /// Python sidecar's unrelated CLI-role vocabulary ("provider"/
    /// "requester"), a different axis this field must never collide with.
    /// NEVER silently defaulted to `"served"` -- a missing/unrecognized
    /// signal must never become a claim; that silent default was the actual
    /// bug this field exists to close.
    pub role: String,
    /// Complementary vantage provenance (2026-09-06 ruling, option C):
    /// `Some("client_egress")` on the `RemoteMesh` dispatch path only -- this
    /// node observed the exchange at its own outbound/client-facing vantage
    /// point, not a serving vantage. `None` on every other path. A top-level
    /// sibling of `role`, mirroring where `capsule_sidecar.py` places its own
    /// (provisional) `observation_point` field. Independent of `role`: one
    /// more honestly-scoped fact, not a restatement of it.
    pub observation_point: Option<String>,
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
            "role": self.role,
            "observation_point": self.observation_point,
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

/// [mesh-fabric-vocab-alignment] `epistemic_type` (the fabric's shared
/// record-header vocabulary convention) for the SAME `x-mesh-poc-v1.role` value this record carries.
/// `None` for `"conflict"`/`"unknown"`/anything else unrecognized -- an
/// ambiguous or unlabelable role must never be rounded up to either claim.
fn epistemic_type_for_role(role: &str) -> Option<&'static str> {
    match role {
        "served" => Some("producer_claim"),
        "requested" => Some("observed_event"),
        _ => None,
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

/// Structural validation ONLY of `compute_attestation.host_binding`
/// (`capsule_emit::capsule::HostBinding`): presence, shape and registered
/// labels. It is mesh-llm's own digest for the exchange under mesh-llm's own
/// construction, so the record joins the host platform's operational log
/// without either side re-canonicalizing the other's bytes.
///
/// INDEPENDENCE RULE (normative): a verifier MUST NOT infer equality,
/// derivation, or transitive coverage between `host_binding.digest` and any
/// other binding on the record (including `agent_input_digest`) merely
/// because they cover the same exchange, share a hash algorithm, or appear
/// in the same signed payload. Two bindings on one record are two
/// independent, co-signed claims. This function never reads or compares
/// against any other field; the `mod tests` `equality_inference_mutant_*`
/// tests show why.
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

/// The `compute_attestation` extension members for one exchange, in the
/// order they are committed: the runtime/model extension draft's
/// `model_revision`, `weights_digest`, `quantization`, `decoding`, `source`,
/// `hardware` and `invocation`, then `epistemic_type` and `x-mesh-poc-v1`.
///
/// `ModelAttestation` has no top-level slot for the model members, so they
/// ride in `compute_attestation`, the one free-form extension point, the same
/// as `x-mesh-poc-v1`. `model_id` is the capsule's
/// `model_attestation.model_id`: this producer serves the model itself, so it
/// is both the requested and the resolved model.
pub fn extensions(mesh_poc: &MeshPocV1, model_id: &str) -> Map<String, Value> {
    let mut members = Map::new();
    let sp = &mesh_poc.serving_provenance;
    let mut model_source = Map::new();
    if let Some(rev) = &sp.model_revision {
        members.insert("model_revision".into(), json!(rev));
        model_source.insert("model_revision".into(), json!("self_reported"));
    }
    if let Some(wd) = &sp.weights_digest {
        // A real SHA-256 of the served GGUF's file bytes (see
        // ServingProvenance::weights_digest's own doc comment) -- `computed`,
        // `scope: "file"` per the draft's definition, never `"tensors"`
        // (only achievable under `attested`).
        members.insert(
            "weights_digest".into(),
            json!({"digest_alg": "SHA-256", "digest": wd, "scope": "file"}),
        );
        model_source.insert("weights_digest".into(), json!("computed"));
    }
    if sp.quantization != "unknown" {
        members.insert("quantization".into(), json!(sp.quantization));
        model_source.insert("quantization".into(), json!("self_reported"));
    }
    let mut decoding = Map::new();
    for key in ["temperature", "seed"] {
        if let Some(v) = mesh_poc.generation_parameters.get(key) {
            decoding.insert(key.to_string(), v.clone());
        }
    }
    if !decoding.is_empty() {
        members.insert("decoding".into(), Value::Object(decoding));
        model_source.insert("decoding".into(), json!("self_reported"));
    }
    if !model_source.is_empty() {
        members.insert("source".into(), Value::Object(model_source));
    }

    // compute_attestation.hardware -- only the two fields this plugin's host
    // event actually carries (accelerator/memory_bytes); `platform` stays
    // absent (an `is_soc` flag is not a platform enum -- never guessed).
    let mut hardware = Map::new();
    let mut hardware_source = Map::new();
    if let Some(gpu) = &sp.hardware_gpu {
        hardware.insert("accelerator".into(), json!(gpu));
        hardware_source.insert("accelerator".into(), json!("os_reported"));
    }
    if let Some(vram) = sp.hardware_vram_bytes {
        hardware.insert("memory_bytes".into(), json!(vram));
        hardware_source.insert("memory_bytes".into(), json!("os_reported"));
    }
    if !hardware.is_empty() {
        hardware.insert("source".into(), Value::Object(hardware_source));
        members.insert("hardware".into(), Value::Object(hardware));
    }

    // compute_attestation.invocation -- requested/resolved are the same
    // self-reported value; usage is the real response `usage`,
    // provider_reported.
    let mut invocation = Map::new();
    let mut invocation_source = Map::new();
    invocation.insert("requested_model_id".into(), json!(model_id));
    invocation_source.insert("requested_model_id".into(), json!("self_reported"));
    invocation.insert("resolved_model_id".into(), json!(model_id));
    invocation_source.insert("resolved_model_id".into(), json!("self_reported"));
    if let Some(usage) = &sp.usage {
        invocation.insert(
            "usage".into(),
            json!({
                "prompt_tokens": usage.prompt_tokens,
                "completion_tokens": usage.completion_tokens,
                "total_tokens": usage.total_tokens,
            }),
        );
        invocation_source.insert("usage".into(), json!("provider_reported"));
    }
    invocation.insert("source".into(), Value::Object(invocation_source));
    members.insert("invocation".into(), Value::Object(invocation));

    // [mesh-fabric-vocab-alignment] additive record-header field, a sibling
    // of x-mesh-poc-v1 (never nested inside it -- epistemic_type is fabric
    // vocabulary, not a PoC extension). Derived from the SAME
    // x-mesh-poc-v1.role signal, never re-guessed: "served" is this node's
    // own claim about what it served (`producer_claim`), "requested" is this
    // node's own observation of what it received (`observed_event`).
    // `role: "conflict"`/`"unknown"` never map to either -- omitted, same
    // "absent, never fabricated" discipline as `role` itself.
    if let Some(epistemic_type) = epistemic_type_for_role(&mesh_poc.role) {
        members.insert("epistemic_type".into(), json!(epistemic_type));
    }
    members.insert("x-mesh-poc-v1".into(), mesh_poc.to_value());
    debug_assert!(members
        .keys()
        .all(|k| !CORE_COMPUTE_ATTESTATION_MEMBERS.contains(&k.as_str())));
    members
}

#[cfg(test)]
mod tests {
    use super::*;
    use capsule_emit::capsule::{CapsuleInput, HostBinding};

    /// A capsule's core input and its Mesh members, sealed together the way
    /// the plugin does.
    struct Input {
        core: CapsuleInput,
        mesh_poc: MeshPocV1,
    }

    fn seal(input: &Input) -> Result<Value, capsule_emit::capsule::SealError> {
        let mut core = input.core.clone();
        core.compute_attestation_extensions = extensions(&input.mesh_poc, &core.model_id);
        capsule_emit::capsule::seal(&core)
    }

    fn base_input() -> Input {
        let mut generation_parameters = Map::new();
        generation_parameters.insert("temperature".into(), json!("0.7"));
        Input {
            core: CapsuleInput {
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
                agent_output_digest: Some("b".repeat(64)),
                tool_calls_digest: None,
                reasoning_digest: None,
                host_binding: None,
                runtime: json!({"name": "runtime"}),
                compute_attestation_extensions: Map::new(),
                effect_status: "confirmed".to_string(),
                effect_type: "inference_completion".to_string(),
                effect_request_digest: Some("a".repeat(64)),
                effect_response_digest: Some("b".repeat(64)),
                effect_attestation: "gate_executed".to_string(),
                disposition_decision: "accept".to_string(),
                disposition_approver: "policy".to_string(),
                disposition_human_disposed: false,
                disposition_verdict_class: "executed".to_string(),
                chain: None,
                store_nonce: "5".repeat(64),
            },
            mesh_poc: MeshPocV1 {
                client_nonce: "c".repeat(32),
                client_nonce_source: "client_supplied".to_string(),
                model_name_digest: "d".repeat(64),
                serving_provenance: ServingProvenance {
                    served_by_node_id: "node-under-test".to_string(),
                    dispatch_path: None,
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
                    peer_capsule_id: None,
                    peer_capsule_id_provenance: None,
                    twin_bracket_id: None,
                },
                role: "served".to_string(),
                observation_point: None,
                generation_parameters,
                latency_ms: "1.0".to_string(),
                binary_attestation: None,
                tee_attestation: None,
            },
        }
    }

    /// The `x-mesh-poc-v1` extension's serving-provenance sub-object of one
    /// sealed capsule.
    fn provenance(capsule: &Value) -> &Value {
        &capsule["model_attestation"]["compute_attestation"]["x-mesh-poc-v1"]["serving_provenance"]
    }

    /// The enriched capsule carries EVERY provenance field the host exposes,
    /// under `x-mesh-poc-v1.serving_provenance`, plus the truthfully-renamed
    /// `model_name_digest`. This is the record that must answer "which model,
    /// at what quantization, on whose hardware, for which exchange".
    #[test]
    fn capsule_carries_full_serving_provenance() {
        let capsule = seal(&base_input()).unwrap();
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

    /// [mesh-fabric-vocab-alignment] `epistemic_type` -- additive, a
    /// top-level sibling of `x-mesh-poc-v1`, derived from the SAME `role`
    /// signal `capsule_mesh_view.label_role()` already treats as
    /// authoritative. `served` -> `producer_claim` (this node's own claim
    /// about what it served); `requested` -> `observed_event` (this node's
    /// own observation of what it received).
    #[test]
    fn epistemic_type_for_served_role_is_producer_claim() {
        let mut input = base_input();
        input.mesh_poc.role = "served".to_string();
        let capsule = seal(&input).unwrap();
        assert_eq!(
            capsule["model_attestation"]["compute_attestation"]["epistemic_type"],
            "producer_claim"
        );
    }

    #[test]
    fn epistemic_type_for_requested_role_is_observed_event() {
        let mut input = base_input();
        input.mesh_poc.role = "requested".to_string();
        let capsule = seal(&input).unwrap();
        assert_eq!(
            capsule["model_attestation"]["compute_attestation"]["epistemic_type"],
            "observed_event"
        );
    }

    /// The mutant this guards against: rounding an ambiguous/unrecognized
    /// role up to either epistemic claim. `conflict`/`unknown` must never
    /// silently become `producer_claim` or `observed_event` -- the field is
    /// absent, same "absent, never fabricated" discipline `role` itself
    /// documents.
    #[test]
    fn epistemic_type_absent_for_conflict_and_unknown_roles() {
        for role in ["conflict", "unknown"] {
            let mut input = base_input();
            input.mesh_poc.role = role.to_string();
            let capsule = seal(&input).unwrap();
            assert!(
                capsule["model_attestation"]["compute_attestation"]
                    .get("epistemic_type")
                    .is_none(),
                "role={role:?} must never carry an epistemic_type claim"
            );
        }
    }

    /// Mutating ANY provenance field changes `capsule_id` — the record is
    /// content-addressed over its provenance, so an attester cannot swap the
    /// served node, exchange id, or token counts without breaking the digest.
    #[test]
    fn mutating_a_provenance_field_changes_capsule_id() {
        let baseline = seal(&base_input()).unwrap();
        let baseline_id = baseline["capsule_id"].as_str().unwrap().to_string();

        // (1) served_by_node_id
        let mut input = base_input();
        input.mesh_poc.serving_provenance.served_by_node_id = "other-node".to_string();
        assert_ne!(seal(&input).unwrap()["capsule_id"], baseline_id.as_str());

        // (2) exchange_id
        let mut input = base_input();
        input.mesh_poc.serving_provenance.exchange_id = "other-exch".to_string();
        assert_ne!(seal(&input).unwrap()["capsule_id"], baseline_id.as_str());

        // (3) quantization (baseline is "Q4_K_M"; mutate to a different quant)
        let mut input = base_input();
        input.mesh_poc.serving_provenance.quantization = "Q8_0".to_string();
        assert_ne!(seal(&input).unwrap()["capsule_id"], baseline_id.as_str());

        // (3b) a model-fidelity field (architecture) is also digest-bound.
        let mut input = base_input();
        input.mesh_poc.serving_provenance.architecture = Some("mistral".to_string());
        assert_ne!(seal(&input).unwrap()["capsule_id"], baseline_id.as_str());

        // (3c) a hardware field (gpu) is also digest-bound.
        let mut input = base_input();
        input.mesh_poc.serving_provenance.hardware_gpu = Some("NVIDIA H100".to_string());
        assert_ne!(seal(&input).unwrap()["capsule_id"], baseline_id.as_str());

        // (3d) the weights digest is also digest-bound -- a quant swap under
        // the same model name records as a changed capsule (it does not
        // prevent the swap; it makes it a signed, non-repudiable fact).
        let mut input = base_input();
        input.mesh_poc.serving_provenance.weights_digest = Some("8".repeat(64));
        assert_ne!(seal(&input).unwrap()["capsule_id"], baseline_id.as_str());

        // (4) usage token counts
        let mut input = base_input();
        input.mesh_poc.serving_provenance.usage = Some(TokenUsage {
            prompt_tokens: 999,
            completion_tokens: 1,
            total_tokens: 1000,
        });
        assert_ne!(seal(&input).unwrap()["capsule_id"], baseline_id.as_str());

        // (5) model_name_digest
        let mut input = base_input();
        input.mesh_poc.model_name_digest = "e".repeat(64);
        assert_ne!(seal(&input).unwrap()["capsule_id"], baseline_id.as_str());
    }

    // =======================================================================
    // twin_bracket_id -- forwarded verbatim from the terminal envelope,
    // never minted or defaulted here (see [`ServingProvenance::twin_bracket_id`]).
    // =======================================================================

    /// Positive vector: when the envelope carried a `twin_bracket_id`, the
    /// sealed record carries it verbatim under `serving_provenance`.
    /// MUTANT: drop the forward (stop copying the field into `ServingProvenance`
    /// before calling `seal`) and this assertion goes red.
    #[test]
    fn twin_bracket_id_present_is_carried_verbatim() {
        let mut input = base_input();
        input.mesh_poc.serving_provenance.twin_bracket_id = Some("twin-abc123".to_string());
        let capsule = seal(&input).unwrap();
        assert_eq!(provenance(&capsule)["twin_bracket_id"], "twin-abc123");
    }

    /// Absence rule: when the envelope carried no `twin_bracket_id` (the
    /// overwhelming majority of exchanges), the key is OMITTED entirely --
    /// never `null` -- so a reader can never mistake an untwinned row for a
    /// half-formed bracket.
    #[test]
    fn twin_bracket_id_absent_when_envelope_carried_none() {
        let capsule = seal(&base_input()).unwrap();
        assert!(
            provenance(&capsule).get("twin_bracket_id").is_none(),
            "an absent twin_bracket_id must be omitted, not null"
        );
    }

    /// Digest-bound: a real `twin_bracket_id` is committed into `capsule_id`
    /// like every other provenance fact, so an attester cannot swap a row
    /// into (or out of) a bracket without changing the sealed record's
    /// content address.
    #[test]
    fn twin_bracket_id_is_digest_bound() {
        let baseline = seal(&base_input()).unwrap();
        let baseline_id = baseline["capsule_id"].as_str().unwrap().to_string();
        let mut input = base_input();
        input.mesh_poc.serving_provenance.twin_bracket_id = Some("twin-abc123".to_string());
        assert_ne!(seal(&input).unwrap()["capsule_id"], baseline_id.as_str());
    }

    /// Two rows of one real twin: both are sealed from their own node's copy
    /// of the SAME host-minted id, so both sealed records carry the
    /// identical `twin_bracket_id` even though everything else about them
    /// (which node served, the exchange id) differs -- this is what lets a
    /// reader bracket the two rows together.
    #[test]
    fn two_rows_sharing_a_twin_bracket_id_carry_the_identical_value() {
        let mut requester = base_input();
        requester.mesh_poc.serving_provenance.served_by_node_id = "node-a".to_string();
        requester.mesh_poc.serving_provenance.exchange_id = "exch-a".to_string();
        requester.mesh_poc.serving_provenance.twin_bracket_id = Some("twin-shared".to_string());

        let mut served = base_input();
        served.mesh_poc.serving_provenance.served_by_node_id = "node-b".to_string();
        served.mesh_poc.serving_provenance.exchange_id = "exch-b".to_string();
        served.mesh_poc.serving_provenance.twin_bracket_id = Some("twin-shared".to_string());

        let requester_capsule = seal(&requester).unwrap();
        let served_capsule = seal(&served).unwrap();
        assert_eq!(
            provenance(&requester_capsule)["twin_bracket_id"],
            provenance(&served_capsule)["twin_bracket_id"]
        );
        assert_eq!(
            provenance(&requester_capsule)["twin_bracket_id"],
            "twin-shared"
        );
        // Different exchanges, same bracket id -- distinct capsule_ids.
        assert_ne!(
            requester_capsule["capsule_id"],
            served_capsule["capsule_id"]
        );
    }

    // =======================================================================
    // host_binding — reverse-direction composition binding
    // =======================================================================

    /// Positive vector: a `host_binding` group carries mesh-llm's own digest
    /// under its own construction, structurally valid per
    /// `validate_host_binding`, and digest-bound into `capsule_id`.
    #[test]
    fn host_binding_present_is_carried_and_valid() {
        let mut input = base_input();
        input.core.host_binding = Some(HostBinding {
            digest: "a6329c5ebb66562f38a8136a8d8511b6aeed166e4c7d889b9133ac96fc49a9d5".to_string(),
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
        let mut other = base_input();
        other.core.host_binding = Some(HostBinding {
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
        let capsule = seal(&base_input()).unwrap();
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
        let mut capsule = seal(&base_input()).unwrap();
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
        let mut capsule = seal(&base_input()).unwrap();
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
        let mut input = base_input();
        input.core.agent_input_digest = "1".repeat(64); // our construction's value
        input.core.host_binding = Some(HostBinding {
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
        let capsule = seal(&base_input()).unwrap();
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
