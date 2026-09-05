//! Ask #5's carrier, minus ask #5's own build: mesh-llm's *existing*
//! `OpenMeshStreamRequest`/`connect_stream` plugin-mesh-stream mechanism
//! (`crates/mesh-llm-host-runtime/src/mesh/plugin_streams.rs`, verified on
//! `main` at `cae3620` and reconfirmed against a fresh `mesh-llm` checkout for
//! this task) already lets a plugin open a bidirectional QUIC stream to the
//! *same plugin* on a target peer, gated on both ends declaring the channel
//! in their manifest (`plugin_event_channel_declared`). This module declares
//! `evidence-request/1` and bridges bytes on both ends -- mesh never parses
//! either side, exactly the `[mesh-e15-evidence-http-route]` door's contract,
//! carried over the mesh instead of a reachable HTTP door. Zero upstream
//! (`mesh-llm`) code.
//!
//! **Responder role** (`on_open_stream`): the host already gated this call on
//! the channel being declared before `connect_stream` ever reaches us, so any
//! `OpenStreamRequest` this handler receives IS a mesh-inbound evidence
//! request (nothing else in this plugin calls `open_stream`/`connect_stream`
//! for anything). We bind a local listener, hand its endpoint back, and once
//! the host bridges the remote QUIC bytes to it, proxy the whole exchange as
//! ONE buffered HTTP POST to the local `evidence_server.py` (E15) door --
//! reusing `answer()` unchanged, never re-implementing it in Rust. A read
//! that never completes (peer hangs) or a POST that never returns cannot wedge
//! the connection open past `RESPONDER_IDLE_TIMEOUT`.
//!
//! **Requester role**: the streamed-HTTP-binding path mesh-llm ships
//! (`handle_streamed_http_binding`) forwards a binding's *static* manifest
//! path/method into `OpenStreamRequest.metadata_json` before any request body
//! exists -- it cannot carry a caller-chosen `target_peer_id`, so it cannot
//! drive an outbound `OpenMeshStreamRequest` on this plugin's behalf. The
//! mechanism that CAN -- `mesh_llm_plugin`'s tool/operation router
//! (`ToolRouter`/`invoke_operation`, reachable locally over
//! `POST /api/plugins/admission-policy/tools/mesh_evidence_request`) -- hands
//! its handler the full JSON arguments AND a `&mut PluginContext` in the same
//! call, so `ask_history.py --via mesh <peer_id>` drives this tool locally;
//! the handler opens the mesh stream, writes the E14 request bytes, and
//! returns whatever the peer's own responder wrote back (Artifact or signed
//! Refusal, untouched) as the tool's JSON result. A peer that never declared
//! the channel drops the stream at the host with no reply; bounded by
//! `REQUESTER_IDLE_TIMEOUT` so that reads a clean failure, never a hang.
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use mesh_llm_plugin::proto::{OpenMeshStreamRequest, OpenStreamRequest, OpenStreamResponse};
use mesh_llm_plugin::{
    LocalStream, PluginContext, PluginError, PluginResult, bind_side_stream,
};
use schemars::JsonSchema;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The mesh channel this plugin declares on both ends -- gates both the
/// outbound `open_outbound_plugin_mesh_stream` call (checked against THIS
/// plugin's own manifest) and the inbound `handle_plugin_mesh_stream` call
/// (checked against the responder's manifest).
pub const EVIDENCE_REQUEST_CHANNEL: &str = "evidence-request/1";

/// The tool name `ask_history.py --via mesh` calls locally
/// (`POST /api/plugins/<plugin_id>/tools/mesh_evidence_request`).
pub const EVIDENCE_REQUEST_OPERATION: &str = "mesh_evidence_request";

/// How long the RESPONDER waits for `evidence_server.py` to answer before
/// giving up on an already-open mesh stream. Bounds a wedged local HTTP door,
/// not the mesh stream itself (mesh-llm's own `idle_timeout_ms` on the
/// `OpenMeshStreamRequest` bounds that separately, host-side). Overridable so
/// a test proving the bound is actually enforced does not have to wait out
/// the production default.
fn responder_http_timeout() -> Duration {
    env_millis("ADMISSION_POLICY_EVIDENCE_HTTP_TIMEOUT_MS", 10_000)
}

/// How long the REQUESTER waits for a response once the mesh stream is open
/// -- covers exactly the "peer never declared the channel, host drops the
/// stream with no reply" case the acceptance check requires read as a clean
/// failure, never a hang.
fn requester_idle_timeout_ms() -> u64 {
    env_millis("ADMISSION_POLICY_MESH_REQUEST_TIMEOUT_MS", 8_000).as_millis() as u64
}

fn env_millis(var: &str, default_ms: u64) -> Duration {
    Duration::from_millis(
        std::env::var(var)
            .ok()
            .and_then(|raw| raw.parse().ok())
            .unwrap_or(default_ms),
    )
}

static STREAM_NONCE: AtomicU64 = AtomicU64::new(1);

fn next_stream_id(prefix: &str) -> String {
    format!(
        "{prefix}-{}-{}",
        std::process::id(),
        STREAM_NONCE.fetch_add(1, Ordering::Relaxed)
    )
}

/// Where this node's own `evidence_server.py` (E15) is listening. Defaults to
/// `evidence_server.py`'s own default port (`--listen-port 8091`) so a manual
/// run needs no extra wiring; the e2e test points this at an isolated port.
fn evidence_server_url() -> String {
    std::env::var("ADMISSION_POLICY_EVIDENCE_SERVER_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8091".to_string())
}

// ---------------------------------------------------------------------
// Responder role: mesh-inbound `evidence-request/1` stream -> local E15 door
// ---------------------------------------------------------------------

/// Registered as this plugin's `on_open_stream` handler. Never fabricates an
/// Artifact/Refusal itself -- a transport failure (local door unreachable,
/// peer went silent) just drops the stream; only `evidence_server.py`'s own
/// `answer()` ever produces a signed response, so nothing unsigned is ever
/// returned in its place.
pub async fn handle_open_stream(
    request: OpenStreamRequest,
    _context: &mut PluginContext<'_>,
) -> PluginResult<Option<OpenStreamResponse>> {
    let listener = bind_side_stream(crate::PLUGIN_ID, &request.stream_id)
        .await
        .map_err(|error| PluginError::internal(error.to_string()))?;
    let response = listener.open_stream_response(&request);

    tokio::spawn(async move {
        if let Err(error) = bridge_inbound_evidence_stream(listener).await {
            tracing::warn!(%error, "mesh evidence-request responder bridge failed");
        }
    });

    Ok(Some(response))
}

async fn bridge_inbound_evidence_stream(
    listener: mesh_llm_plugin::LocalListener,
) -> anyhow::Result<()> {
    let local = listener.accept().await?;
    let (mut read_half, mut write_half) = local.into_split();

    // The remote requester writes the whole E14 request map then half-closes
    // (mirrors mesh-llm's own streamed-http-binding convention: a full write
    // followed by `shutdown()`, never a length prefix) -- read to EOF to get
    // exactly the request bytes, nothing more.
    let mut request_bytes = Vec::new();
    read_half.read_to_end(&mut request_bytes).await?;

    let client = reqwest::Client::builder()
        .timeout(responder_http_timeout())
        .build()?;
    let url = format!("{}/evidence-request", evidence_server_url());
    let response = client
        .post(&url)
        .header("Content-Type", "application/json")
        .body(request_bytes)
        .send()
        .await?;
    let response_bytes = response.bytes().await?;

    write_half.write_all(&response_bytes).await?;
    write_half.shutdown().await?;
    Ok(())
}

// ---------------------------------------------------------------------
// Requester role: local tool call -> outbound `evidence-request/1` stream
// ---------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct MeshEvidenceRequestArgs {
    /// Hex-encoded mesh peer id to ask, e.g. `iroh::EndpointId::to_string()`.
    pub peer_id: String,
    /// The E14 request map, passed through byte-for-byte -- this bridge never
    /// interprets it.
    pub request: serde_json::Value,
}

/// Registered as the `mesh_evidence_request` tool/operation handler
/// (`ToolRouter::add_json`). Returns the peer's raw Artifact-or-Refusal JSON
/// unchanged on success; any failure (unroutable peer, channel undeclared on
/// the peer, response never arrives) surfaces as a tool error -- `PluginError`
/// -- which the host's `/tools/` HTTP route reports as a `502`, never a hang.
pub async fn handle_mesh_evidence_request(
    args: MeshEvidenceRequestArgs,
    context: &mut PluginContext<'_>,
) -> PluginResult<serde_json::Value> {
    if args.peer_id.trim().is_empty() {
        return Err(PluginError::invalid_params("peer_id must not be empty"));
    }

    let open_request = OpenMeshStreamRequest {
        stream_id: next_stream_id("evidence-request"),
        target_peer_id: args.peer_id.clone(),
        plugin_id: String::new(), // host fills this in from the connection.
        channel: EVIDENCE_REQUEST_CHANNEL.to_string(),
        purpose: mesh_llm_plugin::proto::StreamPurpose::Generic as i32,
        mode: mesh_llm_plugin::proto::StreamMode::RawBytes as i32,
        bidirectional: true,
        content_type: Some("application/json".to_string()),
        correlation_id: Some(next_stream_id("evidence-correlation")),
        metadata_json: None,
        expected_bytes: None,
        idle_timeout_ms: Some(requester_idle_timeout_ms()),
    };

    let stream: LocalStream = context
        .connect_mesh_stream(open_request)
        .await
        .map_err(|error| PluginError::internal(format!("could not reach peer: {error}")))?;
    let (mut read_half, mut write_half) = stream.into_split();

    let request_bytes = serde_json::to_vec(&args.request)
        .map_err(|error| PluginError::internal(format!("request is not valid JSON: {error}")))?;

    let write_and_read = async {
        write_half.write_all(&request_bytes).await?;
        write_half.shutdown().await?;
        let mut response_bytes = Vec::new();
        read_half.read_to_end(&mut response_bytes).await?;
        Ok::<Vec<u8>, std::io::Error>(response_bytes)
    };

    let response_bytes = tokio::time::timeout(
        Duration::from_millis(requester_idle_timeout_ms()),
        write_and_read,
    )
    .await
    .map_err(|_| PluginError::internal("peer does not answer evidence requests"))?
    .map_err(|error| PluginError::internal(format!("peer does not answer evidence requests: {error}")))?;

    serde_json::from_slice(&response_bytes)
        .map_err(|error| PluginError::internal(format!("peer returned malformed response: {error}")))
}
