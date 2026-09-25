//! [mesh-closed-wiring-four-gaps] Seam A1 -- the record-push-at-completion
//! transport. Mechanical sibling of `mesh_evidence_bridge.rs`: the SAME
//! `OpenMeshStreamRequest`/`connect_stream` mesh-stream mechanism, a NEW
//! declared channel (`record-push/1`), bridging bytes on both ends straight
//! to `record_push.py`'s already-shipped, already-tested receiver
//! (`evidence_server.py`'s `/evidence/record-push` door, `handle_record_push`)
//! -- never re-implemented in Rust. Zero upstream (`mesh-llm`) code.
//!
//! **Wire shape.** `push_record`'s own contract is "body = the pushed
//! capsule's own canonical JSON bytes -- opaque at the transport level"
//! (`record_push.py` module doc) -- unchanged here. What this module adds on
//! top, ON THE STREAM (never inside the JSON body, so `record_push.py`'s own
//! opacity contract stays intact) is exactly one line before it: the
//! pusher's own self-declared mesh peer id, then `\n`, then the capsule
//! bytes unchanged. The responder splits on the first `\n` and forwards the
//! id as the SAME `X-Mesh-Requester-Id` header `/evidence-request` already
//! uses for its own self-declared caller identity (`evidence_server.py`'s
//! own "relationship gate" doc note) -- one self-attestation convention,
//! reused, not invented twice. `evidence_server.py`'s door verifies the
//! capsule's cryptographic signature against this claimed identity's
//! announced key before ever storing it as a sibling (`record_push.py`'s
//! `handle_record_push`) -- this module never itself authenticates anything;
//! it only carries the claim and the bytes.
//!
//! **Why a self-declared id, not a mesh-authenticated one.** `mesh-llm-plugin
//! 0.76.2`'s `OpenStreamRequest` (verified against the vendored crate
//! source) carries no sender/requester identity field at all, and
//! `PluginContext` exposes no "who is this connection from" accessor -- the
//! RESPONDER genuinely cannot learn the sender's peer id from the mesh
//! transport itself in this SDK version. Self-declaration on the wire, then
//! a REAL cryptographic check against an announced key on the receiving
//! side, is the same discipline `/evidence-request`'s existing
//! `X-Mesh-Requester-Id` self-attestation already uses -- this module does
//! not invent a weaker trust model, it reuses the one already shipped.
//!
//! **Single `on_open_stream` slot.** The plugin SDK gives a plugin exactly
//! ONE `on_open_stream` handler slot (`SimplePlugin::open_stream_handler:
//! Option<OpenStreamHandler>`, verified against the 0.76.2 crate source) and
//! `OpenStreamRequest` carries no channel name to dispatch on -- `main.rs`'s
//! single registered handler dispatches between this module and
//! `mesh_evidence_bridge` by `content_type`, the one field both sides set to
//! a distinct, stable value for exactly this purpose.
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use mesh_llm_plugin::proto::{OpenMeshStreamRequest, OpenStreamRequest, OpenStreamResponse};
use mesh_llm_plugin::{LocalListener, LocalStream, PluginContext, PluginError, PluginResult, bind_side_stream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The mesh channel this module declares on both ends, distinct from
/// `mesh_evidence_bridge::EVIDENCE_REQUEST_CHANNEL`.
pub const RECORD_PUSH_CHANNEL: &str = "record-push/1";

/// The `content_type` both sides of a record-push stream set -- the ONE
/// signal `main.rs`'s single `on_open_stream` handler dispatches on, since
/// `OpenStreamRequest` carries no channel name (see module doc).
pub const RECORD_PUSH_CONTENT_TYPE: &str = "application/x-admission-policy-record-push+json";

fn responder_http_timeout() -> Duration {
    env_millis("ADMISSION_POLICY_EVIDENCE_HTTP_TIMEOUT_MS", 10_000)
}

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

/// Same door this node's own `mesh_evidence_bridge` bridges to -- one E15
/// door, two carriers.
fn evidence_server_url() -> String {
    std::env::var("ADMISSION_POLICY_EVIDENCE_SERVER_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8091".to_string())
}

/// Splits the wire bytes into `(sender_peer_id, capsule_json_bytes)` on the
/// first `\n` -- see module doc's "wire shape" note. `None` when the bytes
/// carry no newline at all (malformed, never a partial/guessed split).
fn split_wire(wire: &[u8]) -> Option<(&str, &[u8])> {
    let newline_at = wire.iter().position(|&b| b == b'\n')?;
    let sender_peer_id = std::str::from_utf8(&wire[..newline_at]).ok()?;
    Some((sender_peer_id, &wire[newline_at + 1..]))
}

// ---------------------------------------------------------------------
// Responder role: mesh-inbound `record-push/1` stream -> local E15 door
// ---------------------------------------------------------------------

/// Registered (via `main.rs`'s dispatching `on_open_stream`) for every
/// inbound stream whose `content_type` is [`RECORD_PUSH_CONTENT_TYPE`].
/// Never fabricates a response itself -- a transport failure just drops the
/// stream; only `evidence_server.py`'s own `handle_record_push` ever
/// produces the `{"status": "received"}` / signed-`Refusal` reply.
pub async fn handle_open_stream(
    request: OpenStreamRequest,
    _context: &mut PluginContext<'_>,
) -> PluginResult<Option<OpenStreamResponse>> {
    let listener = bind_side_stream(crate::PLUGIN_ID, &request.stream_id)
        .await
        .map_err(|error| PluginError::internal(error.to_string()))?;
    let response = listener.open_stream_response(&request);

    tokio::spawn(async move {
        if let Err(error) = bridge_inbound_record_push(listener).await {
            tracing::warn!(%error, "mesh record-push responder bridge failed");
        }
    });

    Ok(Some(response))
}

async fn bridge_inbound_record_push(listener: LocalListener) -> anyhow::Result<()> {
    let local = listener.accept().await?;
    let (mut read_half, mut write_half) = local.into_split();

    let mut wire = Vec::new();
    read_half.read_to_end(&mut wire).await?;
    let (sender_peer_id, capsule_bytes) = split_wire(&wire)
        .ok_or_else(|| anyhow::anyhow!("record-push wire bytes carry no sender-peer-id line"))?;

    let client = reqwest::Client::builder()
        .timeout(responder_http_timeout())
        .build()?;
    let url = format!("{}/evidence/record-push", evidence_server_url());
    let response = client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("X-Mesh-Requester-Id", sender_peer_id)
        .body(capsule_bytes.to_vec())
        .send()
        .await?;
    let response_bytes = response.bytes().await?;

    write_half.write_all(&response_bytes).await?;
    write_half.shutdown().await?;
    Ok(())
}

// ---------------------------------------------------------------------
// Requester role: push this node's own sealed capsule to a peer's door
// ---------------------------------------------------------------------

/// Opens a `record-push/1` mesh stream to `peer_id` and pushes
/// `capsule_json` (this node's own just-sealed capsule, unmodified --
/// `record_push.py`'s "AS TRANSMITTED, never re-signed" invariant), self-
/// declaring `self_peer_id` as the sender (see module doc's "wire shape").
/// Best-effort by design -- the caller (`main.rs`'s seal-on-observe path)
/// logs success/failure and never lets a push failure disturb sealing or
/// channel-message processing, same discipline as
/// `seal_observed_host_exchange`'s own producer-error handling.
pub async fn push_capsule_to_peer(
    context: &mut PluginContext<'_>,
    peer_id: &str,
    self_peer_id: &str,
    capsule_json: &serde_json::Value,
) -> anyhow::Result<()> {
    let open_request = OpenMeshStreamRequest {
        stream_id: next_stream_id("record-push"),
        target_peer_id: peer_id.to_string(),
        plugin_id: String::new(), // host fills this in from the connection.
        channel: RECORD_PUSH_CHANNEL.to_string(),
        purpose: mesh_llm_plugin::proto::StreamPurpose::Generic as i32,
        mode: mesh_llm_plugin::proto::StreamMode::RawBytes as i32,
        bidirectional: true,
        content_type: Some(RECORD_PUSH_CONTENT_TYPE.to_string()),
        correlation_id: Some(next_stream_id("record-push-correlation")),
        metadata_json: None,
        expected_bytes: None,
        idle_timeout_ms: Some(requester_idle_timeout_ms()),
    };

    let stream: LocalStream = context
        .connect_mesh_stream(open_request)
        .await
        .map_err(|error| anyhow::anyhow!("could not reach peer {peer_id}: {error}"))?;
    let (mut read_half, mut write_half) = stream.into_split();

    let mut wire = Vec::with_capacity(self_peer_id.len() + 1);
    wire.extend_from_slice(self_peer_id.as_bytes());
    wire.push(b'\n');
    serde_json::to_writer(&mut wire, capsule_json)?;

    let write_and_read = async {
        write_half.write_all(&wire).await?;
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
    .map_err(|_| anyhow::anyhow!("peer {peer_id} did not acknowledge record-push"))?
    .map_err(|error| anyhow::anyhow!("peer {peer_id} did not acknowledge record-push: {error}"))?;

    let response: serde_json::Value = serde_json::from_slice(&response_bytes)
        .map_err(|error| anyhow::anyhow!("peer {peer_id} returned malformed record-push response: {error}"))?;
    if response.get("reason").is_some() {
        anyhow::bail!("peer {peer_id} refused record-push: {response}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_wire_separates_sender_id_from_capsule_bytes() {
        let wire = b"peer-abc\n{\"capsule_id\":\"x\"}";
        let (sender, body) = split_wire(wire).expect("wire has a newline");
        assert_eq!(sender, "peer-abc");
        assert_eq!(body, b"{\"capsule_id\":\"x\"}");
    }

    #[test]
    fn split_wire_rejects_bytes_with_no_newline() {
        assert!(split_wire(b"no-newline-here").is_none());
    }

    #[test]
    fn split_wire_allows_an_empty_capsule_body() {
        let (sender, body) = split_wire(b"peer-abc\n").expect("wire has a newline");
        assert_eq!(sender, "peer-abc");
        assert!(body.is_empty());
    }
}
