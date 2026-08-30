mod capsule_emit;
mod decision;
mod lifecycle_channel;

use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use capsule_emit::{CapsuleState, HostProvenance, ObservedHostExchange};
use capsule_producer::capsule::TokenUsage;
use decision::Decision;
use lifecycle_channel::{
    HostServingProvenance, MirrorUsage, ObservedLifecycleEvents, OpenAiExchangeEnvelope,
    OPENAI_EXCHANGE_CHANNEL,
};
use mesh_llm_plugin::{
    capability, inference, mesh_channel, plugin, plugin_server_info, PluginMetadata, PluginRuntime,
};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpListener;

const PLUGIN_ID: &str = "admission-policy";
const PLUGIN_VERSION: &str = "0.1.0";
const ENDPOINT_ID: &str = "admission-policy-openai";

/// The set of model names this plugin advertises via `/v1/models` — i.e. the
/// set it will actually be routed requests for. mesh-llm's real model routing
/// (`mesh-llm-host-runtime::network::openai::ingress`) only falls through to a
/// plugin-hosted inference endpoint when no local/remote backend already
/// serves the named model, matched by exact string — there is no wildcard.
/// An admission-policy plugin therefore enforces its policy by being the
/// registered provider for every blocked name it knows about in advance, not
/// by observing every exchange regardless of model (see docs/PROTOCOL-NOTE.md
/// for why that's a real architectural difference from the private spike).
fn blocked_models() -> Vec<String> {
    std::env::var("ADMISSION_POLICY_BLOCKED_MODELS")
        .ok()
        .map(|raw| raw.split(',').map(|s| s.trim().to_string()).collect())
        .filter(|v: &Vec<String>| !v.is_empty())
        .unwrap_or_else(|| vec!["blocked-test-model".to_string()])
}

/// Where the persistent signing key + durable ledger + observed-lifecycle-
/// events log live. Defaults to a directory beside the plugin binary's CWD
/// so a manual run doesn't silently scatter state; the e2e test points this
/// at an isolated directory per run.
fn data_dir() -> PathBuf {
    std::env::var("ADMISSION_POLICY_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("./admission-policy-data"))
}

#[derive(Clone)]
struct AppState {
    models: Arc<Vec<String>>,
    capsules: Arc<CapsuleState>,
    /// The host serving-provenance the plugin has observed on the
    /// `openai.exchange.v1` channel, so the seal path can read the host's real
    /// quantization/hardware/model-digest for the served model.
    lifecycle_events: Arc<ObservedLifecycleEvents>,
}

/// Adapt the lifecycle-channel's mirror of the host `serving_provenance` block
/// into the capsule-emit capture struct. A straight field copy — every field
/// stays `Option`, so a fact the host did not report remains `None` and lands
/// as an honest `unknown`/`null` in the capsule (never fabricated here).
fn host_provenance_from(observed: HostServingProvenance) -> HostProvenance {
    HostProvenance {
        served_by_node_id: observed.served_by_node_id,
        hostname: observed.hostname,
        quantization: observed.quantization,
        architecture: observed.architecture,
        context_length: observed.context_length,
        parameter_size: observed.parameter_size,
        layer_count: observed.layer_count,
        model_identity_hash: observed.model_identity_hash,
        model_canonical_ref: observed.model_canonical_ref,
        model_revision: observed.model_revision,
        gpu: observed.gpu,
        vram_bytes: observed.vram_bytes,
        is_soc: observed.is_soc,
    }
}

/// Map the mirror's real token usage into the capsule-producer `TokenUsage`.
/// A straight copy of real counts — never fabricated.
fn token_usage_from(usage: MirrorUsage) -> TokenUsage {
    TokenUsage {
        prompt_tokens: usage.prompt_tokens,
        completion_tokens: usage.completion_tokens,
        total_tokens: usage.total_tokens,
    }
}

/// Seal a capsule for a host-served terminal exchange this plugin only OBSERVED.
/// Best-effort observability: a producer error is logged, never propagated (an
/// observe-path failure must not disturb the host). The three real facts —
/// serving provenance, usage, request digest — come straight off the terminal
/// event; nothing is fabricated.
fn seal_observed_host_exchange(capsules: &CapsuleState, envelope: &OpenAiExchangeEnvelope) {
    let host_provenance = envelope
        .serving_provenance
        .clone()
        .map(host_provenance_from)
        .unwrap_or_default();
    let usage = envelope.usage.map(token_usage_from);
    let observed = ObservedHostExchange {
        model: &envelope.model,
        exchange_id: envelope.exchange_id.as_deref(),
        request_digest: envelope.request_digest.as_deref(),
        // The host-forwarded digests over the REAL response body: bind
        // agent_output_digest to the real response, and seal the real
        // tool_calls_digest / reasoning_digest (absent when the model had none).
        response_digest: envelope.response_digest.as_deref(),
        tool_calls_digest: envelope.tool_calls_digest.as_deref(),
        reasoning_digest: envelope.reasoning_digest.as_deref(),
        usage,
        host_provenance,
    };
    match capsules.emit_for_observed_host_exchange(&observed) {
        Ok(emitted) => {
            tracing::info!(
                capsule_id = %emitted.capsule_id,
                model = %envelope.model,
                "SEALED AAC for host-served (observed) exchange"
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to seal capsule for observed host-served exchange");
        }
    }
}

async fn list_models(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "object": "list",
        "data": state.models
            .iter()
            .map(|id| json!({"id": id, "object": "model", "owned_by": PLUGIN_ID}))
            .collect::<Vec<_>>(),
    }))
}

async fn chat_completions(
    State(state): State<AppState>,
    body: axum::body::Bytes,
) -> (StatusCode, Json<Value>) {
    let started = Instant::now();
    match decision::decide(&body) {
        Decision::Allow => {
            let parsed_request = serde_json::from_slice::<Value>(&body).ok();
            let model = parsed_request
                .as_ref()
                .and_then(|v| v.get("model").and_then(|m| m.as_str()))
                .unwrap_or("unknown-model")
                .to_string();
            let client_nonce = parsed_request
                .as_ref()
                .and_then(|v| v.get("client_nonce").and_then(|n| n.as_str()))
                .map(str::to_string);

            // Stable per-exchange correlation id for the response and the
            // capsule's `serving_provenance.exchange_id`, so both views of the
            // same exchange share one id (mirrors the host's `x-request-id` /
            // `exchange_id` lineage — the plugin mints its own when serving
            // directly). `usage` is an OpenAI-shaped `usage` object so a real
            // token count would flow straight through `parse_usage`; the stub
            // reports zero work honestly (empty completion) rather than faking
            // counts it did not produce.
            let exchange_id = format!("chatcmpl-{}", agent_input_digest_short(&body));
            let mut response = json!({
                "id": exchange_id,
                "object": "chat.completion",
                "choices": [],
                "usage": {
                    "prompt_tokens": 0,
                    "completion_tokens": 0,
                    "total_tokens": 0,
                },
                "admission_policy": {"decision": "allow"},
            });
            let response_bytes = serde_json::to_vec(&response).expect("response is valid JSON");
            let latency_ms = started.elapsed().as_secs_f64() * 1000.0;

            // The host's real quantization/hardware/model-digest for this model,
            // as most recently observed on the openai.exchange.v1 channel. `None`
            // when the host has published none yet -> capsule keeps honest
            // defaults; never fabricated.
            let host_provenance = state
                .lifecycle_events
                .latest_provenance_for_model(&model)
                .map(host_provenance_from);

            match state.capsules.emit_for_exchange(&capsule_emit::ExchangeRecord {
                model: &model,
                client_nonce: client_nonce.as_deref(),
                request_bytes: &body,
                response_bytes: &response_bytes,
                latency_ms,
                exchange_id: Some(&exchange_id),
                // The requesting party beyond the client nonce is not carried on
                // this direct-serve path — recorded as "unknown", not invented.
                requesting_party: None,
                host_provenance,
            }) {
                Ok(emitted) => {
                    tracing::info!(capsule_id = %emitted.capsule_id, %model, "emitted AAC for admitted exchange");
                    response["admission_policy"]["capsule_id"] = json!(emitted.capsule_id);
                    response["admission_policy"]["capsule"] = emitted.capsule;
                }
                Err(error) => {
                    // Capsule production is best-effort observability, not a
                    // gate: never let a producer bug turn an admitted
                    // exchange into a denied one.
                    tracing::warn!(%error, "failed to emit capsule for admitted exchange");
                }
            }
            (StatusCode::OK, Json(response))
        }
        Decision::Deny { reason } => (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": {
                    "message": reason,
                    "type": "admission_policy_denied",
                    "code": "blocked_model_prefix",
                }
            })),
        ),
    }
}

/// A short, deterministic per-exchange tag derived from the request body, used
/// to mint a stable correlation id shared by the response `id` and the
/// capsule's `serving_provenance.exchange_id`. Deterministic (not random) so
/// the same request yields the same id — a real correlation handle, not noise.
fn agent_input_digest_short(request_bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(request_bytes);
    hex::encode(&digest[..8])
}

async fn serve_admission_http(listener: TcpListener, state: AppState) {
    let app = Router::new()
        .route("/v1/models", get(list_models))
        .route("/v1/chat/completions", post(chat_completions))
        .with_state(state);
    axum::serve(listener, app)
        .await
        .expect("admission-policy HTTP server crashed");
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let address = format!("http://127.0.0.1:{port}");
    let models = blocked_models();

    let data_dir = data_dir();
    let capsules = Arc::new(CapsuleState::open(&data_dir, PLUGIN_ID)?);
    tracing::info!(
        chain_head = ?capsules.chain_head(),
        "capsule-producer ready"
    );
    let lifecycle_events = Arc::new(ObservedLifecycleEvents::open(&data_dir)?);

    let capsules_for_handler = capsules.clone();
    let app_state = AppState {
        models: Arc::new(models),
        capsules,
        lifecycle_events: lifecycle_events.clone(),
    };
    tokio::spawn(serve_admission_http(listener, app_state));

    let lifecycle_events_for_handler = lifecycle_events.clone();
    let plugin = plugin! {
        metadata: PluginMetadata::new(
            PLUGIN_ID,
            PLUGIN_VERSION,
            plugin_server_info(
                PLUGIN_ID,
                PLUGIN_VERSION,
                "Admission policy",
                "Denies OpenAI-compatible exchanges whose model matches a blocked prefix, and emits a signed chained ledgered AAC for every one it admits.",
                None::<String>,
            ),
        ),
        provides: [capability("admission_policy.v1")],
        mesh: [mesh_channel(OPENAI_EXCHANGE_CHANNEL)],
        inference: [inference::provider(ENDPOINT_ID, address)],
        on_channel_message: move |message, _context| {
            let lifecycle_events = lifecycle_events_for_handler.clone();
            let capsules = capsules_for_handler.clone();
            Box::pin(async move {
                if message.channel == OPENAI_EXCHANGE_CHANNEL {
                    match serde_json::from_slice::<OpenAiExchangeEnvelope>(&message.body) {
                        Ok(envelope) => {
                            // Seal-on-observe: a HOST-SERVED terminal exchange
                            // (a real loaded GGUF routed host->native-runtime)
                            // never reaches this plugin's own HTTP handler, so
                            // nothing else produces a capsule for it. When the
                            // observed terminal carries real served-model
                            // identity (only a real GGUF does — the plugin's own
                            // stub does not, so it is not double-sealed), seal a
                            // capsule from the observed serving provenance + real
                            // usage + host-forwarded request digest.
                            if ObservedLifecycleEvents::is_sealable_host_served(&envelope) {
                                seal_observed_host_exchange(&capsules, &envelope);
                            }
                            lifecycle_events.record(envelope);
                        }
                        Err(error) => {
                            tracing::warn!(%error, "unparseable openai.exchange.v1 envelope");
                        }
                    }
                }
                Ok(())
            })
        },
    };

    PluginRuntime::run(plugin).await
}
