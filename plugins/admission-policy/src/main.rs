mod capsule_emit;
mod decision;
mod lifecycle_channel;

use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use capsule_emit::CapsuleState;
use decision::Decision;
use lifecycle_channel::{ObservedLifecycleEvents, OpenAiExchangeEnvelope, OPENAI_EXCHANGE_CHANNEL};
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

            let mut response = json!({
                "id": "admission-policy-allow-stub",
                "object": "chat.completion",
                "choices": [],
                "admission_policy": {"decision": "allow"},
            });
            let response_bytes = serde_json::to_vec(&response).expect("response is valid JSON");
            let latency_ms = started.elapsed().as_secs_f64() * 1000.0;

            match state.capsules.emit_for_exchange(
                &model,
                client_nonce.as_deref(),
                &body,
                &response_bytes,
                latency_ms,
            ) {
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

    let app_state = AppState {
        models: Arc::new(models),
        capsules,
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
            Box::pin(async move {
                if message.channel == OPENAI_EXCHANGE_CHANNEL {
                    match serde_json::from_slice::<OpenAiExchangeEnvelope>(&message.body) {
                        Ok(envelope) => lifecycle_events.record(envelope),
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
