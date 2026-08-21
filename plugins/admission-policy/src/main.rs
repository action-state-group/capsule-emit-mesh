mod decision;

use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use decision::Decision;
use mesh_llm_plugin::{
    capability, inference, plugin, plugin_server_info, PluginMetadata, PluginRuntime,
};
use serde_json::{json, Value};
use std::sync::Arc;
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

async fn list_models(State(models): State<Arc<Vec<String>>>) -> Json<Value> {
    Json(json!({
        "object": "list",
        "data": models
            .iter()
            .map(|id| json!({"id": id, "object": "model", "owned_by": PLUGIN_ID}))
            .collect::<Vec<_>>(),
    }))
}

async fn chat_completions(body: axum::body::Bytes) -> (StatusCode, Json<Value>) {
    match decision::decide(&body) {
        Decision::Allow => (
            StatusCode::OK,
            Json(json!({
                "id": "admission-policy-allow-stub",
                "object": "chat.completion",
                "choices": [],
                "admission_policy": {"decision": "allow"},
            })),
        ),
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

async fn serve_admission_http(listener: TcpListener, models: Vec<String>) {
    let app = Router::new()
        .route("/v1/models", get(list_models))
        .route("/v1/chat/completions", post(chat_completions))
        .with_state(Arc::new(models));
    axum::serve(listener, app)
        .await
        .expect("admission-policy HTTP server crashed");
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let address = format!("http://127.0.0.1:{port}");
    let models = blocked_models();

    tokio::spawn(serve_admission_http(listener, models));

    let plugin = plugin! {
        metadata: PluginMetadata::new(
            PLUGIN_ID,
            PLUGIN_VERSION,
            plugin_server_info(
                PLUGIN_ID,
                PLUGIN_VERSION,
                "Admission policy",
                "Denies OpenAI-compatible exchanges whose model matches a blocked prefix.",
                None::<String>,
            ),
        ),
        provides: [capability("admission_policy.v1")],
        inference: [inference::provider(ENDPOINT_ID, address)],
    };

    PluginRuntime::run(plugin).await
}
