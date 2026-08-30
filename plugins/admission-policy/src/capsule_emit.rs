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

/// The generation-parameter (sampling knob) keys carried verbatim in the
/// capsule, in step with the Python reference's `GENERATION_PARAM_KEYS`
/// (`capsule_sidecar.py`). These are the settings the CLIENT asked for in the
/// request -- requested, not proven-effective -- and are legible policy values
/// (not prompt content), so they ride as-is rather than digested. Kept
/// byte-identical to the Python list so both capture paths seal the SAME param
/// set.
const GENERATION_PARAM_KEYS: &[&str] = &[
    "temperature",
    "top_p",
    "top_k",
    "min_p",
    "seed",
    "max_tokens",
    "max_completion_tokens",
    "n",
    "presence_penalty",
    "frequency_penalty",
    "repeat_penalty",
    "stop",
];

/// Lift the generation parameters the client ACTUALLY sent in this request body
/// into a map for the capsule, mirroring the Python sidecar's
/// `build_capsule` allowlist comprehension. Honest-by-absence: a key that was
/// not present in the request (or was JSON `null`) is OMITTED, never defaulted
/// to a fabricated value -- so a request that carried only `temperature` seals
/// exactly `temperature`, and the old hardcoded `temperature=0.0` is gone.
/// Values are stringified through the same `stringify_floats` used for the
/// digest path, so `0.7` -> `"0.7"` (float) while integers like `seed`/`n`
/// stay JSON numbers -- matching the Python reference's `_stringify_floats`
/// convention exactly, keeping the sealed shape stable across implementations.
/// A non-JSON or non-object body yields an empty map (no params claimed).
fn parse_generation_parameters(request_bytes: &[u8]) -> Map<String, Value> {
    let mut out = Map::new();
    let Ok(Value::Object(request)) = serde_json::from_slice::<Value>(request_bytes) else {
        return out;
    };
    for &key in GENERATION_PARAM_KEYS {
        match request.get(key) {
            Some(value) if !value.is_null() => {
                out.insert(key.to_string(), stringify_floats(value.clone()));
            }
            _ => {}
        }
    }
    out
}

/// The OPTIONAL labeled sub-digests over one response body: `tool_calls_digest`
/// and `reasoning_digest`, each the canonical `jcs::json_digest` (plain JCS,
/// matching the Python reference `capsule_ledger/conversation/exchange.py`'s
/// `digest_conversation_exchange`) of the flattened `tool_calls` /
/// `reasoning_content` across the response's assistant message(s). Each is
/// `None` -- and then ABSENT from the sealed capsule, never a fabricated digest
/// over `[]` -- when the response carried none. Used by the plugin-served path,
/// which holds the response bytes directly (the host-served observe path instead
/// binds the digests the host forwarded). No float-stringification: tool_calls /
/// reasoning are strings/structural JSON with no floats, so plain JCS matches
/// the Python reference exactly.
fn output_sub_digests(response_bytes: &[u8]) -> (Option<String>, Option<String>) {
    let Ok(value) = serde_json::from_slice::<Value>(response_bytes) else {
        return (None, None);
    };
    let mut tool_calls: Vec<Value> = Vec::new();
    let mut reasoning: Vec<Value> = Vec::new();
    if let Some(choices) = value.get("choices").and_then(Value::as_array) {
        for choice in choices {
            let Some(message) = choice.get("message") else {
                continue;
            };
            if let Some(tcs) = message.get("tool_calls").and_then(Value::as_array) {
                tool_calls.extend(tcs.iter().cloned());
            }
            if let Some(r) = message.get("reasoning_content").filter(|r| !r.is_null()) {
                if !matches!(r, Value::String(s) if s.is_empty()) {
                    reasoning.push(r.clone());
                }
            }
        }
    }
    let tool_calls_digest = (!tool_calls.is_empty())
        .then(|| jcs::json_digest(&Value::Array(tool_calls)))
        .transpose()
        .ok()
        .flatten();
    let reasoning_digest = (!reasoning.is_empty())
        .then(|| jcs::json_digest(&Value::Array(reasoning)))
        .transpose()
        .ok()
        .flatten();
    (tool_calls_digest, reasoning_digest)
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
        // This path serves the response itself, so it holds the bytes -- compute
        // the OPTIONAL tool_calls/reasoning sub-digests directly (absent when the
        // model emitted none). Real digests over the real served response.
        let (tool_calls_digest, reasoning_digest) = output_sub_digests(response_bytes);

        let mut ledger = self.ledger.lock().expect("capsule ledger mutex poisoned");
        let chain = ledger.chain_head().map(|parent| ChainLink {
            parent_capsule_id: parent.to_string(),
            relation: "follows".to_string(),
        });

        // The REAL sampling settings the client requested, parsed straight from
        // the request body this path holds -- only the keys actually present,
        // never a fabricated default.
        let generation_parameters = parse_generation_parameters(request_bytes);

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
            // OPTIONAL labeled sub-digests over the served response body; absent
            // when the model emitted none (never fabricated).
            tool_calls_digest,
            reasoning_digest,
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

/// One host-served exchange this plugin only OBSERVED (never served itself),
/// reconstructed from its `openai.exchange.v1` terminal event. Unlike
/// [`ExchangeRecord`], the plugin holds no request/response *bytes* here -- a
/// host-served GGUF exchange routes host->native-runtime and never reaches this
/// plugin's HTTP handler. What it does hold, off the terminal event, is:
///   - the host's real `serving_provenance` (model identity + hardware),
///   - the backend's real `usage` (token counts),
///   - the canonical digest of the REAL request body (`request_digest`),
///     forwarded by the host so the capsule's `agent_input_digest` binds the
///     real bytes without the plugin ever seeing the prompt.
/// Every field is real-or-honest-default; nothing is fabricated.
pub struct ObservedHostExchange<'a> {
    pub model: &'a str,
    /// Host-minted per-exchange correlation id from the terminal event.
    pub exchange_id: Option<&'a str>,
    /// Canonical JSON-DIGEST of the REAL request body, forwarded by the host.
    /// `None` when the host did not forward one (older host / non-JSON body) --
    /// the capsule then records an honest "unknown-request" sentinel, never a
    /// fabricated digest.
    pub request_digest: Option<&'a str>,
    /// Canonical JSON-DIGEST of the REAL response body, forwarded by the host
    /// (computed at its JSON-relay delivery point). When present, the capsule's
    /// `agent_output_digest` binds the REAL response bytes rather than merely
    /// the terminal accounting facts. `None` on a host that did not forward one
    /// (older host / streamed body) -- the capsule then falls back to the
    /// observed-terminal-facts digest, documented as such, never fabricated.
    pub response_digest: Option<&'a str>,
    /// Canonical JSON-DIGEST of the flattened `tool_calls` the model emitted,
    /// forwarded by the host (byte-for-byte the Python reference
    /// `json_digest(tool_calls)`). `None` -- and then ABSENT from the capsule,
    /// never a fabricated digest over `[]` -- when the model emitted none.
    pub tool_calls_digest: Option<&'a str>,
    /// Canonical JSON-DIGEST of the model's `reasoning_content`, forwarded by
    /// the host. `None` -- and ABSENT from the capsule -- for a non-reasoning
    /// model (honest null), never fabricated.
    pub reasoning_digest: Option<&'a str>,
    /// The backend's real token usage from the terminal event.
    pub usage: Option<TokenUsage>,
    /// The host's serving provenance for this served model.
    pub host_provenance: HostProvenance,
}

impl CapsuleState {
    /// Seal, sign, chain, and ledger one host-served exchange this plugin only
    /// OBSERVED on the `openai.exchange.v1` channel -- closing the gap where a
    /// host-served GGUF (routed host->native-runtime, never through this
    /// plugin's own handler) produced NO capsule at all. The three real facts
    /// come straight off the host's terminal event (serving provenance, usage,
    /// request digest); no bytes are handled here.
    ///
    /// DIGEST BINDING (honest, precise):
    ///   * `agent_input_digest` / `effect_request_digest` = the host-forwarded
    ///     `request_digest`, the canonical JSON-DIGEST of the REAL request body
    ///     (computed host-side the same way this plugin's `canonical_body_digest`
    ///     does, so the two are comparable). When the host forwarded none, an
    ///     explicit `unknown-request:<model>` sentinel is bound instead -- an
    ///     honest marker of absence, never a fabricated body digest.
    ///   * `agent_output_digest` / `effect_response_digest` = the canonical
    ///     JSON-DIGEST of the observed TERMINAL FACTS (model + real usage), NOT
    ///     the served response body: the host streams the response to the client
    ///     and only the token `usage` returns to the publish site, so the plugin
    ///     never sees the response bytes. This digest therefore binds *what the
    ///     host attested about the output* (its real token accounting), and is
    ///     documented as such -- it is a real digest of real observed facts, not
    ///     a stand-in for a body it never had. See PROTOCOL-NOTE.md for what full
    ///     response-body binding would additionally require host-side.
    pub fn emit_for_observed_host_exchange(
        &self,
        observed: &ObservedHostExchange,
    ) -> anyhow::Result<EmittedCapsule> {
        let ObservedHostExchange {
            model,
            exchange_id,
            request_digest,
            response_digest,
            tool_calls_digest,
            reasoning_digest,
            usage,
            host_provenance,
        } = observed;
        let (model, exchange_id, request_digest, response_digest, tool_calls_digest, reasoning_digest, usage) = (
            *model,
            *exchange_id,
            *request_digest,
            *response_digest,
            *tool_calls_digest,
            *reasoning_digest,
            usage.clone(),
        );
        let host = host_provenance.clone();

        // agent_input_digest: the host-forwarded canonical request-body digest
        // when present; an explicit honest sentinel otherwise (never fabricated).
        let agent_input_digest = request_digest
            .map(str::to_string)
            .unwrap_or_else(|| format!("unknown-request:{model}"));

        // agent_output_digest: PREFER the host-forwarded canonical digest of the
        // REAL response body (computed host-side at its JSON-relay delivery
        // point, the same plain-JCS `json_digest` a verifier recomputes) -- this
        // binds the capsule to what the model actually produced. When the host
        // forwarded none (older host, or a streamed body it could not buffer),
        // fall back to the canonical digest of the observed TERMINAL FACTS
        // (model + real usage) -- a real digest of real observed output-
        // accounting, documented as NOT a response-body digest, never fabricated.
        let agent_output_digest = match response_digest {
            Some(rd) => rd.to_string(),
            None => {
                let mut output_facts = Map::new();
                output_facts.insert("model".into(), Value::String(model.to_string()));
                if let Some(u) = usage.as_ref() {
                    let mut usage_obj = Map::new();
                    usage_obj.insert("prompt_tokens".into(), Value::from(u.prompt_tokens));
                    usage_obj.insert("completion_tokens".into(), Value::from(u.completion_tokens));
                    usage_obj.insert("total_tokens".into(), Value::from(u.total_tokens));
                    output_facts.insert("usage".into(), Value::Object(usage_obj));
                }
                jcs::json_digest(&Value::Object(output_facts))?
            }
        };

        let mut ledger = self.ledger.lock().expect("capsule ledger mutex poisoned");
        let chain = ledger.chain_head().map(|parent| ChainLink {
            parent_capsule_id: parent.to_string(),
            relation: "follows".to_string(),
        });

        // Honest-by-absence: a host-served exchange routes host->native-runtime
        // and never reaches this plugin's handler, so it holds NO request bytes
        // here (only the host-forwarded request DIGEST) -- the client's sampling
        // settings are simply not observable on this path. We therefore seal an
        // EMPTY generation-parameter set rather than the old fabricated
        // `temperature=0.0`; absent facts are recorded as absent, never invented.
        // (Full generation-parameter capture on the observe path would require
        // the host to forward them on the terminal event; see PROTOCOL-NOTE.md.)
        let generation_parameters = Map::new();

        let input = CapsuleInput {
            action_id: format!("mesh-poc/capsule-emit-mesh-host-served/{agent_input_digest}"),
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
            // The REAL labeled sub-digests the host forwarded off the response
            // body -- OPTIONAL, absent when the model emitted none (never
            // fabricated). This is where the real `tool_calls_digest` lands.
            tool_calls_digest: tool_calls_digest.map(str::to_string),
            reasoning_digest: reasoning_digest.map(str::to_string),
            runtime: format!(
                "{}:admission-policy-plugin/mesh-llm-host-runtime",
                "0".repeat(64)
            ),
            mesh_poc: MeshPocV1 {
                // A host-served exchange carries no client nonce to this plugin
                // (it never reached this plugin's handler) -- honest default.
                client_nonce: "host-served-no-nonce".to_string(),
                client_nonce_source: "host_served_observed".to_string(),
                model_name_digest: hex_sha256(model.as_bytes()),
                serving_provenance: ServingProvenance {
                    served_by_node_id: host
                        .served_by_node_id
                        .clone()
                        .unwrap_or_else(|| self.node_id.clone()),
                    // Requesting party is not carried on the host-served
                    // observe path -- honest "unknown", never invented.
                    requesting_party: "unknown".to_string(),
                    exchange_id: exchange_id.unwrap_or("unknown").to_string(),
                    hostname: host.hostname.clone(),
                    quantization: host
                        .quantization
                        .clone()
                        .unwrap_or_else(|| "unknown".to_string()),
                    hardware_gpu: host.gpu.clone(),
                    hardware_vram_bytes: host.vram_bytes,
                    hardware_device: None,
                    hardware_is_soc: host.is_soc,
                    architecture: host.architecture.clone(),
                    context_length: host.context_length,
                    parameter_size: host.parameter_size.clone(),
                    layer_count: host.layer_count,
                    model_identity_hash: host.model_identity_hash.clone(),
                    model_canonical_ref: host.model_canonical_ref.clone(),
                    model_revision: host.model_revision.clone(),
                    // The REAL token counts from the host terminal event.
                    usage,
                },
                generation_parameters,
                // Latency is not carried on the observe path (the plugin did not
                // time the host's own dispatch) -- honest zero-marker, not faked.
                latency_ms: "0.000".to_string(),
            },
            effect_status: "confirmed".to_string(),
            effect_type: "inference_completion".to_string(),
            effect_request_digest: agent_input_digest,
            effect_response_digest: agent_output_digest,
            effect_attestation: "host_served_observed".to_string(),
            disposition_decision: "accept".to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// PARITY PIN: `output_sub_digests` over the REAL SETI@Home / web_search
    /// response computes a `tool_calls_digest` byte-for-byte identical to the
    /// Python reference `agent_action_capsule.json_digest(tool_calls)` — the
    /// value recorded requester-side in the live demo
    /// (`_work/mesh-live-demo/b-tool_calls.json`). A non-reasoning model yields
    /// an absent reasoning digest (honest null), never fabricated.
    #[test]
    fn output_sub_digests_over_real_seti_response_matches_python_reference() {
        let body = br#"{"id":"chatcmpl-seti","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"","tool_calls":[{"function":{"arguments":"{\"query\": \"mesh-llm vs SETI@Home\"}","name":"web_search"},"id":"call_719a955fb46a41008dd847d412f00795","type":"function"}]},"finish_reason":"tool_calls"}]}"#;
        let (tool_calls_digest, reasoning_digest) = output_sub_digests(body);
        assert_eq!(
            tool_calls_digest.as_deref(),
            Some("f294be8a53bb9c29cd94472721f0857591f34b23fe010882de79b9fb210b1395"),
            "plugin tool_calls_digest must equal the Python reference json_digest(tool_calls)"
        );
        assert!(
            reasoning_digest.is_none(),
            "a non-reasoning model must yield an absent reasoning digest, not a fabricated one"
        );
    }

    /// A response with no tool call yields an absent tool_calls digest — never a
    /// digest over `[]`.
    #[test]
    fn output_sub_digests_absent_when_no_tool_calls() {
        let body = br#"{"choices":[{"message":{"role":"assistant","content":"hi"}}]}"#;
        let (tcd, rd) = output_sub_digests(body);
        assert!(tcd.is_none());
        assert!(rd.is_none());
    }

    /// A request carrying a spread of sampling knobs (float, int, and the
    /// llama.cpp-style `top_k`/`min_p`/`repeat_penalty`) seals ALL of them, with
    /// floats stringified (matching the digest-path convention) and ints kept as
    /// JSON numbers. This is the direct fix for the hardcoded `temperature=0.0`.
    #[test]
    fn parse_generation_parameters_captures_all_present_sampling_knobs() {
        let body = br#"{
            "model": "m",
            "messages": [{"role": "user", "content": "hi"}],
            "temperature": 0.7,
            "top_p": 0.95,
            "top_k": 40,
            "min_p": 0.05,
            "seed": 12345,
            "repeat_penalty": 1.1,
            "max_tokens": 512,
            "n": 1,
            "stop": ["\n\n"]
        }"#;
        let gp = parse_generation_parameters(body);
        // Floats stringified through the same convention as the digest path.
        assert_eq!(gp["temperature"], Value::String("0.7".into()));
        assert_eq!(gp["top_p"], Value::String("0.95".into()));
        assert_eq!(gp["min_p"], Value::String("0.05".into()));
        assert_eq!(gp["repeat_penalty"], Value::String("1.1".into()));
        // Integers stay JSON numbers.
        assert_eq!(gp["top_k"], Value::from(40));
        assert_eq!(gp["seed"], Value::from(12345));
        assert_eq!(gp["max_tokens"], Value::from(512));
        assert_eq!(gp["n"], Value::from(1));
        // Non-numeric values (stop list) carried verbatim.
        assert_eq!(gp["stop"], Value::Array(vec![Value::String("\n\n".into())]));
        // NOT the old fabricated default.
        assert_ne!(gp["temperature"], Value::String("0.0".into()));
    }

    /// Honest-by-absence: a request that sent ONLY `temperature` and `seed`
    /// seals exactly those two keys — no other sampling knob is defaulted into
    /// the capsule. Absent stays absent.
    #[test]
    fn parse_generation_parameters_absent_stays_absent() {
        let body = br#"{"model":"m","temperature":0.2,"seed":7}"#;
        let gp = parse_generation_parameters(body);
        assert_eq!(gp.len(), 2, "only the two present keys are sealed");
        assert!(gp.contains_key("temperature"));
        assert!(gp.contains_key("seed"));
        // None of the omitted knobs are present — not even as a zero/default.
        for absent in [
            "top_p",
            "top_k",
            "min_p",
            "max_tokens",
            "max_completion_tokens",
            "n",
            "presence_penalty",
            "frequency_penalty",
            "repeat_penalty",
            "stop",
        ] {
            assert!(
                !gp.contains_key(absent),
                "{absent} was not in the request and must NOT be sealed"
            );
        }
    }

    /// A JSON `null` value is treated as absent (not sealed as a fabricated
    /// value), matching the Python reference's `is not None` guard.
    #[test]
    fn parse_generation_parameters_treats_null_as_absent() {
        let body = br#"{"temperature":0.5,"top_p":null}"#;
        let gp = parse_generation_parameters(body);
        assert!(gp.contains_key("temperature"));
        assert!(!gp.contains_key("top_p"));
    }

    /// A non-object / non-JSON body claims NO generation parameters (empty map),
    /// never a fabricated default.
    #[test]
    fn parse_generation_parameters_empty_for_non_object_body() {
        assert!(parse_generation_parameters(b"not json").is_empty());
        assert!(parse_generation_parameters(b"[1,2,3]").is_empty());
    }

    /// END-TO-END (served path): a real admitted exchange whose request carried
    /// `temperature`, `top_k`, `min_p`, `repeat_penalty`, and `seed` seals a
    /// capsule whose `x-mesh-poc-v1.generation_parameters` holds exactly those,
    /// and NO hardcoded `temperature=0.0`.
    #[test]
    fn emit_for_exchange_seals_the_real_requested_generation_parameters() {
        let dir = std::env::temp_dir().join(format!("cap-gp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let state = CapsuleState::open(&dir, "node-under-test").expect("open state");

        let request_body = br#"{"model":"m","messages":[{"role":"user","content":"hi"}],"temperature":0.7,"top_k":40,"min_p":0.05,"repeat_penalty":1.1,"seed":99}"#;
        let response_body = br#"{"id":"x","choices":[{"message":{"role":"assistant","content":"hello"}}],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}"#;
        let exchange = ExchangeRecord {
            model: "m",
            client_nonce: Some("nonce-1"),
            request_bytes: request_body,
            response_bytes: response_body,
            latency_ms: 12.0,
            exchange_id: Some("e-1"),
            requesting_party: Some("party-1"),
            host_provenance: None,
        };
        let emitted = state.emit_for_exchange(&exchange).expect("seal exchange");
        let gp = &emitted.capsule["model_attestation"]["compute_attestation"]
            ["x-mesh-poc-v1"]["generation_parameters"];
        assert_eq!(gp["temperature"], Value::String("0.7".into()));
        assert_eq!(gp["min_p"], Value::String("0.05".into()));
        assert_eq!(gp["repeat_penalty"], Value::String("1.1".into()));
        assert_eq!(gp["top_k"], Value::from(40));
        assert_eq!(gp["seed"], Value::from(99));
        // Only what was requested — no other knob defaulted in.
        let obj = gp.as_object().expect("generation_parameters is an object");
        assert_eq!(obj.len(), 5);
        // The old fabricated default is gone.
        assert_ne!(gp["temperature"], Value::String("0.0".into()));

        // When AAC_CAPSULE_EXPORT_DIR is set, export the sealed capsule + its
        // detached COSE_Sign1 + the pubkey so an EXTERNAL verifier (the Python
        // agent_action_capsule / Go COSE reference) can confirm a capsule that
        // carries REAL requested generation parameters still verifies GREEN and
        // its capsule_id (which commits generation_parameters) is intact.
        if let Ok(export_dir) = std::env::var("AAC_CAPSULE_EXPORT_DIR") {
            let export = std::path::Path::new(&export_dir);
            std::fs::create_dir_all(export).expect("mk export dir");
            // Export the EXACT canonical payload bytes the COSE statement signs
            // (not a pretty reserialization), so an external verifier can
            // byte-compare the capsule.json against the COSE payload.
            std::fs::write(
                export.join("SEALED-with-generation-params.json"),
                capsule_producer::capsule::payload_bytes(&emitted.capsule),
            )
            .expect("write capsule");
            let cose_src = dir
                .join("ledger")
                .join("signed-statements")
                .join(format!("{}.cose", emitted.capsule_id));
            std::fs::copy(&cose_src, export.join("SEALED-with-generation-params.cose"))
                .expect("copy cose");
            std::fs::copy(
                dir.join("keys").join("node-key.pub.pem"),
                export.join("node-key.pub.pem"),
            )
            .expect("copy pubkey");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The host-served OBSERVE path holds no request bytes (only a forwarded
    /// digest), so it seals an EMPTY generation-parameter set — never the old
    /// fabricated `temperature=0.0`. Absent facts stay absent.
    #[test]
    fn observed_host_exchange_seals_no_fabricated_generation_parameters() {
        let dir = std::env::temp_dir().join(format!("cap-gpo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let state = CapsuleState::open(&dir, "node-under-test").expect("open state");
        let observed = ObservedHostExchange {
            model: "m",
            exchange_id: Some("e"),
            request_digest: Some("a".repeat(64).leak()),
            response_digest: None,
            tool_calls_digest: None,
            reasoning_digest: None,
            usage: None,
            host_provenance: HostProvenance::default(),
        };
        let emitted = state
            .emit_for_observed_host_exchange(&observed)
            .expect("seal");
        let gp = &emitted.capsule["model_attestation"]["compute_attestation"]
            ["x-mesh-poc-v1"]["generation_parameters"];
        let obj = gp.as_object().expect("generation_parameters is an object");
        assert!(
            obj.is_empty(),
            "observe path holds no request -> no sampling knobs, and NO fabricated temperature=0.0"
        );
        assert!(gp.get("temperature").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// END-TO-END: a host-served observed exchange that forwarded a real
    /// `tool_calls_digest` and `response_digest` seals a capsule whose
    /// `compute_attestation.tool_calls_digest` equals the forwarded (Python-
    /// reference) value, and whose `agent_output_digest` binds the forwarded
    /// REAL response digest — not the terminal-facts fallback.
    #[test]
    fn observed_host_exchange_seals_real_tool_calls_and_response_digest() {
        let dir = std::env::temp_dir().join(format!("cap-tcd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let state = CapsuleState::open(&dir, "node-under-test").expect("open state");

        // The REAL served SETI@Home response body carrying the model's real
        // web_search tool call (the exact tool_calls from the live-demo capture
        // _work/mesh-live-demo/b-tool_calls.json), plus real usage. The host
        // computes response_digest / tool_calls_digest over exactly this body at
        // its JSON-relay delivery point; we reproduce those here to bind the
        // exported capsule to real values throughout (no placeholder digests).
        let response_body = br#"{"id":"chatcmpl-seti","object":"chat.completion","created":1788060371,"model":"llama-3.2-3b-instruct","choices":[{"index":0,"message":{"role":"assistant","content":"","tool_calls":[{"function":{"arguments":"{\"query\": \"mesh-llm vs SETI@Home\"}","name":"web_search"},"id":"call_719a955fb46a41008dd847d412f00795","type":"function"}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":202,"completion_tokens":25,"total_tokens":227}}"#;
        // Real response-body digest (host's `response_digest`) and real
        // tool_calls_digest (host's `tool_calls_digest`) over that body.
        let response_digest = canonical_body_digest(response_body).expect("resp digest");
        let (tool_calls_digest_owned, reasoning_digest_owned) = output_sub_digests(response_body);
        let tool_calls_digest = tool_calls_digest_owned.expect("real tool_calls digest");
        // Independent sanity: the tool_calls_digest equals the Python-reference value.
        assert_eq!(
            tool_calls_digest,
            "f294be8a53bb9c29cd94472721f0857591f34b23fe010882de79b9fb210b1395"
        );
        assert!(reasoning_digest_owned.is_none());
        let observed = ObservedHostExchange {
            model: "llama-3.2-3b-instruct",
            exchange_id: Some("exch-seti"),
            request_digest: Some(
                "a6329c5ebb66562f38a8136a8d8511b6aeed166e4c7d889b9133ac96fc49a9d5",
            ),
            response_digest: Some(&response_digest),
            tool_calls_digest: Some(&tool_calls_digest),
            reasoning_digest: None,
            usage: Some(TokenUsage {
                prompt_tokens: 202,
                completion_tokens: 25,
                total_tokens: 227,
            }),
            host_provenance: HostProvenance {
                architecture: Some("llama".to_string()),
                model_identity_hash: Some("904548955b8a6478".to_string()),
                ..Default::default()
            },
        };
        let emitted = state
            .emit_for_observed_host_exchange(&observed)
            .expect("seal observed host exchange");
        let ca = &emitted.capsule["model_attestation"]["compute_attestation"];
        // The REAL tool_calls_digest is sealed into the capsule.
        assert_eq!(ca["tool_calls_digest"], tool_calls_digest);
        // agent_output_digest binds the forwarded REAL response digest.
        assert_eq!(ca["agent_output_digest"], response_digest);
        // Non-reasoning model -> reasoning_digest omitted entirely (honest null).
        assert!(ca.get("reasoning_digest").is_none());

        // When AAC_CAPSULE_EXPORT_DIR is set, export the sealed capsule + its
        // detached COSE_Sign1 statement + the signing pubkey to that dir, so an
        // EXTERNAL verifier (agent-action-capsule / the Rust verify_capsule bin)
        // can confirm the real-tool_calls capsule verifies GREEN out-of-process.
        if let Ok(export_dir) = std::env::var("AAC_CAPSULE_EXPORT_DIR") {
            let export = std::path::Path::new(&export_dir);
            std::fs::create_dir_all(export).expect("mk export dir");
            std::fs::write(
                export.join("SEALED-with-tool-calls.json"),
                serde_json::to_vec_pretty(&emitted.capsule).unwrap(),
            )
            .expect("write capsule");
            let cose_src = dir
                .join("ledger")
                .join("signed-statements")
                .join(format!("{}.cose", emitted.capsule_id));
            std::fs::copy(&cose_src, export.join("SEALED-with-tool-calls.cose"))
                .expect("copy cose");
            std::fs::copy(
                dir.join("keys").join("node-key.pub.pem"),
                export.join("node-key.pub.pem"),
            )
            .expect("copy pubkey");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// When the host forwarded NO response digest, `agent_output_digest` falls
    /// back to the observed-terminal-facts digest (documented as such), and a
    /// tool_calls_digest is still absent when none was forwarded.
    #[test]
    fn observed_host_exchange_falls_back_when_no_response_digest_forwarded() {
        let dir = std::env::temp_dir().join(format!("cap-fb-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let state = CapsuleState::open(&dir, "node-under-test").expect("open state");
        let observed = ObservedHostExchange {
            model: "m",
            exchange_id: Some("e"),
            request_digest: Some("a".repeat(64).leak()),
            response_digest: None,
            tool_calls_digest: None,
            reasoning_digest: None,
            usage: None,
            host_provenance: HostProvenance {
                architecture: Some("llama".to_string()),
                ..Default::default()
            },
        };
        let emitted = state
            .emit_for_observed_host_exchange(&observed)
            .expect("seal");
        let ca = &emitted.capsule["model_attestation"]["compute_attestation"];
        assert!(ca.get("tool_calls_digest").is_none());
        // Fallback output digest is a real 64-hex digest of the terminal facts.
        assert_eq!(ca["agent_output_digest"].as_str().unwrap().len(), 64);
        let _ = std::fs::remove_dir_all(&dir);
    }

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
