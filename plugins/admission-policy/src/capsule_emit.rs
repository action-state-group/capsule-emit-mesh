//! Wires `capsule-producer` (COSE-sign -> chain -> ledger) into this plugin,
//! closing the #1332 integration gap: previously `capsule-producer` and the
//! admission plugin were two crates with zero shared dependency (see
//! `adv-mesh-1332-e2e-scorecard`). Every ALLOWED chat-completion exchange
//! this plugin itself serves is turned into a signed, chained, ledgered AAC
//! (`x-mesh-poc-v1` mapping) -- `effect_request_digest`/`effect_response_digest`
//! are the canonical JSON-DIGEST (RFC 8785 JCS) of the parsed request/response
//! body, matching this crate's own `jcs::json_digest` and the Python sidecar's
//! `capsule_sidecar.digest_json` (spec §5.1) -- NOT a raw hash of the wire
//! bytes, so reserializing the identical semantic content (key order,
//! whitespace) does not change the digest, and it stays comparable across
//! implementations. Mutating the actual content still changes `capsule_id`.

use capsule_producer::capsule::{
    seal, CapsuleInput, ChainLink, MeshPocV1, ServingProvenance, TokenUsage,
};
use capsule_producer::cose::{build_signed_statement, SignedStatementInput};
use capsule_producer::jcs;
use capsule_producer::keys::{self, KeyPair};
use capsule_producer::ledger::Ledger;
use capsule_producer::timestamp::utc_now_iso8601;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Mutex;

/// Recursively replace JSON floats with their exact decimal-string form,
/// mirroring `capsule_sidecar._stringify_floats` in the Python reference:
/// the JSON-DIGEST (spec §5.1) refuses any float in a digest-bearing value
/// (float serialization isn't cross-implementation deterministic), and
/// OpenAI-shaped chat request/response bodies are full of floats
/// (temperature, top_p, penalties, ...). `python_repr_f64` is not a claim of
/// byte-parity with Python's `repr()` for every float (neither the Python
/// docstring it mirrors makes that claim) -- it is deterministic for this
/// plugin's own digest and matches Python for the ordinary decimal range
/// chat-completion parameters actually use.
fn stringify_floats(value: Value) -> Value {
    match value {
        Value::Number(n) => match n.as_f64() {
            Some(f) if n.is_f64() && !(n.is_i64() || n.is_u64()) => {
                Value::String(python_repr_f64(f))
            }
            _ => Value::Number(n),
        },
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(k, v)| (k, stringify_floats(v)))
                .collect(),
        ),
        Value::Array(arr) => Value::Array(arr.into_iter().map(stringify_floats).collect()),
        other => other,
    }
}

fn python_repr_f64(f: f64) -> String {
    let s = format!("{f}");
    if s.contains('.') || s.contains('e') || s.contains('E') {
        s
    } else {
        format!("{s}.0")
    }
}

/// The canonical JSON-DIGEST of a request/response body: parse as JSON,
/// stringify floats, then `jcs::json_digest`. See the module docs for why
/// this replaces a raw hash of the wire bytes.
fn canonical_body_digest(bytes: &[u8]) -> anyhow::Result<String> {
    let value: Value = serde_json::from_slice(bytes)?;
    Ok(jcs::json_digest(&stringify_floats(value))?)
}

/// Extract real token accounting from an OpenAI-shaped response body's `usage`
/// object (`openai-frontend`'s `Usage`: `prompt_tokens` / `completion_tokens` /
/// `total_tokens`). Returns `None` — never a fabricated zero — when the served
/// body carried no well-formed `usage` (e.g. an allow-stub or error body). This
/// is the only honest source of usage the plugin has: the counts come from the
/// response the host actually produced, not from anything this plugin invents.
fn parse_usage(response_bytes: &[u8]) -> Option<TokenUsage> {
    let value: Value = serde_json::from_slice(response_bytes).ok()?;
    let usage = value.get("usage")?;
    let prompt_tokens = usage.get("prompt_tokens")?.as_u64()?;
    let completion_tokens = usage.get("completion_tokens")?.as_u64()?;
    // total_tokens: prefer the server-reported value; fall back to the sum only
    // when the body omitted it (still a real derivation, not an invention).
    let total_tokens = usage
        .get("total_tokens")
        .and_then(Value::as_u64)
        .unwrap_or_else(|| prompt_tokens.saturating_add(completion_tokens));
    Some(TokenUsage {
        prompt_tokens,
        completion_tokens,
        total_tokens,
    })
}

const CAPSULE_CONTENT_TYPE: &str =
    "application/vnd.agent-action-capsule+json; profile=draft-mih-scitt-agent-action-capsule-02";

pub struct CapsuleState {
    keys: KeyPair,
    ledger: Mutex<Ledger>,
    node_id: String,
}

pub struct EmittedCapsule {
    pub capsule_id: String,
    pub capsule: Value,
}

/// The host's serving-provenance facts for the served model, captured from the
/// `openai.exchange.v1` terminal event (mirror `lifecycle_channel::
/// HostServingProvenance`). Every field is `Option`: a fact the host did not
/// report stays `None` and lands as an honest `unknown`/`null` in the capsule —
/// never fabricated. Passed as owned data (not a borrow of the channel state)
/// so the emit path holds no lock on the lifecycle store.
#[derive(Clone, Default)]
pub struct HostProvenance {
    pub served_by_node_id: Option<String>,
    pub hostname: Option<String>,
    pub quantization: Option<String>,
    pub architecture: Option<String>,
    pub context_length: Option<u32>,
    pub parameter_size: Option<String>,
    pub layer_count: Option<u32>,
    pub model_identity_hash: Option<String>,
    pub model_canonical_ref: Option<String>,
    pub model_revision: Option<String>,
    pub gpu: Option<String>,
    pub vram_bytes: Option<u64>,
    pub is_soc: Option<bool>,
}

/// One admitted exchange to seal into a capsule — the raw request/response
/// bytes (digested, never stored raw) plus the provenance metadata the host
/// exposed for it. Grouped into a struct so the provenance surface can grow
/// without churning the `emit_for_exchange` signature.
pub struct ExchangeRecord<'a> {
    pub model: &'a str,
    pub client_nonce: Option<&'a str>,
    pub request_bytes: &'a [u8],
    pub response_bytes: &'a [u8],
    pub latency_ms: f64,
    /// Stable per-exchange correlation id — the host's `exchange_id` /
    /// response `id` / `x-request-id` lineage, so the record ties back to the
    /// host's own terminal-event log. `None` -> `"unknown"`, never faked.
    pub exchange_id: Option<&'a str>,
    /// Requesting party / client identity beyond the (optional) client nonce.
    /// `None` -> `"unknown"`, never invented.
    pub requesting_party: Option<&'a str>,
    /// The host's serving provenance for this model, captured from the
    /// `openai.exchange.v1` terminal event. `None` when the host has published
    /// none yet — quantization/hardware/model-digest then stay honest defaults.
    pub host_provenance: Option<HostProvenance>,
}

impl CapsuleState {
    /// Loads (or creates, on first run) a persistent Ed25519 signing key and
    /// opens the durable local ledger under `data_dir` -- both restart-safe,
    /// mirroring the acceptance already proven in isolation by
    /// `mesh-rust-capsule-production-m2`'s `chain_ledger_conformance` test.
    pub fn open(data_dir: &Path, node_id: impl Into<String>) -> anyhow::Result<Self> {
        let keys = keys::load_or_create(&data_dir.join("keys"))?;
        let (ledger, report) = Ledger::open(&data_dir.join("ledger"))?;
        tracing::info!(
            recovered_entries = report.valid_entries,
            "capsule-producer ledger opened"
        );
        Ok(Self {
            keys,
            ledger: Mutex::new(ledger),
            node_id: node_id.into(),
        })
    }

    /// Not read by this binary today (the e2e test reads the persisted PEM
    /// straight off disk in the plugin's data dir, matching how a real
    /// verifier would) -- kept as the public accessor a future `/v1/pubkey`
    /// debug endpoint or key-rotation caller would need.
    #[allow(dead_code)]
    pub fn public_key_pem(&self) -> String {
        self.keys.public_key_pem()
    }

    pub fn chain_head(&self) -> Option<String> {
        self.ledger
            .lock()
            .expect("capsule ledger mutex poisoned")
            .chain_head()
            .map(str::to_string)
    }

    /// Seal, sign, chain, and ledger one admitted exchange this plugin's own
    /// `/v1/chat/completions` handler just served.
    pub fn emit_for_exchange(&self, exchange: &ExchangeRecord) -> anyhow::Result<EmittedCapsule> {
        let ExchangeRecord {
            model,
            client_nonce,
            request_bytes,
            response_bytes,
            latency_ms,
            exchange_id,
            requesting_party,
            host_provenance,
        } = exchange;
        let (model, client_nonce, request_bytes, response_bytes, latency_ms, exchange_id, requesting_party) =
            (*model, *client_nonce, *request_bytes, *response_bytes, *latency_ms, *exchange_id, *requesting_party);
        // Honest defaults for every host-provenance fact; each is overwritten
        // only if the host actually reported it (never fabricated).
        let host = host_provenance.clone().unwrap_or_default();
        let agent_input_digest = canonical_body_digest(request_bytes)?;
        let agent_output_digest = canonical_body_digest(response_bytes)?;
        let usage = parse_usage(response_bytes);

        let mut ledger = self.ledger.lock().expect("capsule ledger mutex poisoned");
        let chain = ledger.chain_head().map(|parent| ChainLink {
            parent_capsule_id: parent.to_string(),
            relation: "follows".to_string(),
        });

        let mut generation_parameters = Map::new();
        generation_parameters.insert("temperature".into(), Value::String("0.0".into()));

        let input = CapsuleInput {
            action_id: format!("mesh-poc/capsule-emit-mesh-integration/{agent_input_digest}"),
            action_type: "decide".to_string(),
            operator: "capsule-emit-mesh-poc-rust".to_string(),
            developer: "capsule-producer/0.2.0".to_string(),
            timestamp: utc_now_iso8601(),
            domain: Some("action".to_string()),
            provenance: Some("collector".to_string()),
            model_id: model.to_string(),
            provider: "mesh-llm".to_string(),
            agent_input_digest: agent_input_digest.clone(),
            agent_output_digest: agent_output_digest.clone(),
            runtime: format!(
                "{}:admission-policy-plugin/mesh-llm-host-runtime",
                "0".repeat(64)
            ),
            mesh_poc: MeshPocV1 {
                client_nonce: client_nonce.unwrap_or("sidecar-generated").to_string(),
                client_nonce_source: if client_nonce.is_some() {
                    "client_supplied"
                } else {
                    "sidecar_generated_fallback"
                }
                .to_string(),
                // Renamed from the overclaiming `model_package_digest`: this is
                // SHA-256 of the model NAME only, not the weights/package. The
                // real package digest lives in the Python `model_identity.py`
                // path; the live plugin only has the request's model name.
                model_name_digest: hex_sha256(model.as_bytes()),
                serving_provenance: ServingProvenance {
                    // Prefer the host event's serving node id; fall back to this
                    // emitting node (single-node PoC) when the host reported none.
                    served_by_node_id: host
                        .served_by_node_id
                        .clone()
                        .unwrap_or_else(|| self.node_id.clone()),
                    requesting_party: requesting_party.unwrap_or("unknown").to_string(),
                    exchange_id: exchange_id.unwrap_or("unknown").to_string(),
                    hostname: host.hostname.clone(),
                    // Quantization from the host serving-provenance block when it
                    // carried one; else "unknown" — never guessed.
                    quantization: host
                        .quantization
                        .clone()
                        .unwrap_or_else(|| "unknown".to_string()),
                    // Serving hardware from the host serving-provenance block.
                    // `hardware_device` stays None (host carries is_soc, not a
                    // cpu/cuda/metal device enum) — never fabricated.
                    hardware_gpu: host.gpu.clone(),
                    hardware_vram_bytes: host.vram_bytes,
                    hardware_device: None,
                    hardware_is_soc: host.is_soc,
                    // Model identity / fidelity from the host block.
                    architecture: host.architecture.clone(),
                    context_length: host.context_length,
                    parameter_size: host.parameter_size.clone(),
                    layer_count: host.layer_count,
                    model_identity_hash: host.model_identity_hash.clone(),
                    model_canonical_ref: host.model_canonical_ref.clone(),
                    model_revision: host.model_revision.clone(),
                    // Real token counts from the response body's `usage`, if any.
                    usage,
                },
                generation_parameters,
                latency_ms: format!("{latency_ms:.3}"),
            },
            effect_status: "confirmed".to_string(),
            effect_type: "inference_completion".to_string(),
            effect_request_digest: agent_input_digest,
            effect_response_digest: agent_output_digest,
            effect_attestation: "gate_executed".to_string(),
            disposition_decision: "accept".to_string(),
            // §5.4: disposition.approver MUST be `human` or `policy` -- the
            // admission-policy plugin is the latter (an automated policy
            // engine, not a human disposer), never its own plugin name.
            disposition_approver: "policy".to_string(),
            disposition_human_disposed: false,
            disposition_verdict_class: "executed".to_string(),
            chain,
        };

        let capsule = seal(&input)?;
        let capsule_id = capsule["capsule_id"]
            .as_str()
            .expect("seal() always sets capsule_id")
            .to_string();
        let payload = capsule_producer::capsule::payload_bytes(&capsule);
        let statement = build_signed_statement(
            &SignedStatementInput {
                payload: &payload,
                issuer: &self.node_id,
                subject: &capsule_id,
                content_type: CAPSULE_CONTENT_TYPE,
            },
            &self.keys.signing_key,
        );
        ledger.append(&capsule, &statement)?;

        Ok(EmittedCapsule {
            capsule_id,
            capsule,
        })
    }
}

fn hex_sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [adv-run-2-fix-batch] B1 regression: two byte-different, semantically
    /// identical request bodies (key order + whitespace only) must digest to
    /// the SAME value. Before the fix, `emit_for_exchange` hashed the raw wire
    /// bytes (`hex_sha256`), so this pair produced two different digests --
    /// the exact defect this test pins closed. Reproduced against the
    /// pre-fix `hex_sha256(bytes)` path directly, for contrast.
    #[test]
    fn canonical_body_digest_is_stable_across_key_order_and_whitespace() {
        let a = br#"{"model":"m","temperature":0.7}"#;
        let b = br#"{"temperature": 0.7, "model": "m"}"#;

        let digest_a = canonical_body_digest(a).expect("digest a");
        let digest_b = canonical_body_digest(b).expect("digest b");
        assert_eq!(
            digest_a, digest_b,
            "canonical_body_digest must be format-invariant"
        );

        // contrast: the pre-fix raw-byte hash IS format-sensitive -- proves
        // this pair is a real positive control, not a vacuous equality.
        assert_ne!(
            hex_sha256(a),
            hex_sha256(b),
            "sanity: raw hex_sha256 over wire bytes must differ for this pair \
             (otherwise the pair doesn't exercise the bug this test guards)"
        );
    }

    /// [adv-run-2-fix-batch] B1: Rust<->Python digest-equality. The expected
    /// digest was computed by running the actual Python reference,
    /// `capsule_sidecar.digest_json`, over the identical JSON value:
    ///
    ///   python3 -c "
    ///   from capsule_sidecar import digest_json
    ///   print(digest_json({
    ///       'model': 'hermes-2-pro-mistral-7b',
    ///       'messages': [{'role': 'user', 'content': 'hello'}],
    ///       'temperature': 0.7,
    ///       'top_p': 1.0,
    ///       'max_tokens': 512,
    ///   }))"
    ///
    /// `top_p: 1.0` exercises the whole-number-float edge case
    /// (`python_repr_f64` must emit "1.0", not Rust's default "1") that a
    /// naive float-to-string port would get wrong.
    #[test]
    fn canonical_body_digest_matches_python_reference_digest_json() {
        let body = br#"{"model": "hermes-2-pro-mistral-7b", "messages": [{"role": "user", "content": "hello"}], "temperature": 0.7, "top_p": 1.0, "max_tokens": 512}"#;
        let expected = "a6329c5ebb66562f38a8136a8d8511b6aeed166e4c7d889b9133ac96fc49a9d5";
        assert_eq!(canonical_body_digest(body).expect("digest"), expected);
    }

    /// `parse_usage` lifts REAL token counts from the response body's `usage`
    /// object — the only honest source of usage the plugin has.
    #[test]
    fn parse_usage_reads_real_token_counts_from_the_response_body() {
        let body = br#"{"id":"x","usage":{"prompt_tokens":128,"completion_tokens":64,"total_tokens":192}}"#;
        let usage = parse_usage(body).expect("usage present");
        assert_eq!(usage.prompt_tokens, 128);
        assert_eq!(usage.completion_tokens, 64);
        assert_eq!(usage.total_tokens, 192);
    }

    /// A body with no `usage` yields `None` — never a fabricated zero-usage
    /// object. Absence of a fact is recorded as absence, not invented as zero.
    #[test]
    fn parse_usage_is_none_when_the_body_has_no_usage() {
        let body = br#"{"id":"x","choices":[]}"#;
        assert!(parse_usage(body).is_none());
    }

    /// When the body omits `total_tokens`, it is DERIVED from the two real
    /// counts (a genuine sum), not left blank or faked.
    #[test]
    fn parse_usage_derives_total_from_the_two_real_counts_when_absent() {
        let body = br#"{"usage":{"prompt_tokens":10,"completion_tokens":5}}"#;
        let usage = parse_usage(body).expect("usage present");
        assert_eq!(usage.total_tokens, 15);
    }

    #[test]
    fn python_repr_f64_keeps_the_decimal_point_python_repr_does() {
        assert_eq!(python_repr_f64(1.0), "1.0");
        assert_eq!(python_repr_f64(0.0), "0.0");
        assert_eq!(python_repr_f64(0.7), "0.7");
    }
}
