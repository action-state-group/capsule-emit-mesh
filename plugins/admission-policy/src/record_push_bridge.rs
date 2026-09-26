//! Seam A1 -- the record-push-at-completion
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
//! **The pushing peer's mesh node id is NOT capturable here either
//! (re-verified against both the 0.76.2 proto and the mesh-llm host source).** Every
//! `OpenStreamRequest` field the responder sees (`stream_id`,
//! `content_type`, `correlation_id`, `metadata_json`, ...) is copied
//! VERBATIM from the requester's own `OpenMeshStreamRequest` by the host's
//! `open_stream_request_from_mesh_request` -- all requester-controlled, so
//! anything carried there (including a node id tucked into `metadata_json`)
//! would be one more self-declaration, not a transport attestation. The
//! receiving host DOES hold the transport-authenticated remote identity --
//! its inbound handler is `handle_plugin_mesh_stream(_remote:
//! iroh::EndpointId, ..)` off the QUIC connection -- but it discards
//! `_remote` and never surfaces it to the plugin. Until the SDK grows a
//! host-filled source-peer field on `OpenStreamRequest`, a
//! `received_from_node_id` cannot be recorded honestly, so it is not
//! recorded at all (never synthesized); the ledger carries only the
//! door-verified self-declared `received_from`.
//!
//! **Single `on_open_stream` slot.** The plugin SDK gives a plugin exactly
//! ONE `on_open_stream` handler slot (`SimplePlugin::open_stream_handler:
//! Option<OpenStreamHandler>`, verified against the 0.76.2 crate source) and
//! `OpenStreamRequest` carries no channel name to dispatch on -- `main.rs`'s
//! single registered handler dispatches between this module and
//! `mesh_evidence_bridge` by `content_type`, the one field both sides set to
//! a distinct, stable value for exactly this purpose.
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use mesh_llm_plugin::proto::{OpenMeshStreamRequest, OpenStreamRequest, OpenStreamResponse};
use mesh_llm_plugin::{LocalListener, LocalStream, PluginContext, PluginError, PluginResult, bind_side_stream};
use tokio::io::AsyncWriteExt;

use crate::capsule_emit::{CapsuleState, ReceivedHalfProvenance};

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
///
/// REPLY CONTRACT (revised for the ack-before-seal fix): a transport failure
/// just drops the stream, and the door's own reply -- success or signed
/// `Refusal` -- is forwarded byte-for-byte, with ONE exception this bridge
/// itself mints: when the door accepted+stored the half but this node could
/// NOT seal its citing record (see [`SEAL_FAILED_REFUSAL_REASON`]), the peer
/// gets an unsigned `{"reason": ...}` refusal INSTEAD of the door's success
/// bytes. "received" on this wire therefore always implies "cited" -- the
/// success ack is only ever written AFTER the citing record is durably on
/// our chain, so a crash/cancel can no longer leave the door's store and our
/// chain divergent behind an ack the peer will never retry.
///
/// `capsules` -- this node's own
/// `CapsuleState` (the SAME single-writer ledger every other local capsule is
/// sealed onto). After the Python door confirms the pushed half verified and
/// was stored in the held-artifact store `received-capsules.jsonl`, this
/// responder seals a LOCAL CITING record of the receiving event onto OUR
/// chain -- the foreign body NEVER enters `capsules.jsonl`.
pub async fn handle_open_stream(
    request: OpenStreamRequest,
    _context: &mut PluginContext<'_>,
    capsules: Arc<CapsuleState>,
) -> PluginResult<Option<OpenStreamResponse>> {
    let listener = bind_side_stream(crate::PLUGIN_ID, &request.stream_id)
        .await
        .map_err(|error| PluginError::internal(error.to_string()))?;
    let response = listener.open_stream_response(&request);

    // The bridge itself must run off this handler (the host needs the
    // OpenStreamResponse back before it will bridge any bytes to the
    // listener), so ONE task is spawned per stream -- but the citing-record
    // seal is AWAITED INSIDE the bridge BEFORE the success ack is written
    // (see `bridge_inbound_record_push`), never re-detached: a seal failure
    // (or a shutdown that drops this task mid-bridge) can only ever leave
    // the peer WITHOUT an ack -- so it retries -- never with an ack for a
    // half our chain did not cite.
    tokio::spawn(async move {
        if let Err(error) = bridge_inbound_record_push(listener, capsules).await {
            tracing::warn!(%error, "mesh record-push responder bridge failed");
        }
    });

    Ok(Some(response))
}

/// True when the door's JSON reply is a success (`{"status": "received"}`),
/// false for a signed `Refusal` (carries `reason`). Mirrors
/// `push_capsule_to_peer`'s own `response.get("reason").is_some()` convention.
fn door_accepted(response: &serde_json::Value) -> bool {
    response.get("reason").is_none() && response.get("status").and_then(|s| s.as_str()) == Some("received")
}

/// The `reason` of the ONE reply this bridge mints itself (unsigned -- the
/// door signs its own refusals; this one is the bridge's, see
/// `handle_open_stream`'s reply contract): the door verified+stored the half
/// but the local citing-record seal failed, so the peer must NOT be told
/// "received" (it would never retry, leaving the door's store and our chain
/// divergent). The peer's next push retries the seal; the door re-stores the
/// artifact idempotently-enough and the citing dedup seals at most one record.
const SEAL_FAILED_REFUSAL_REASON: &str = "citing_record_seal_failed";

fn seal_failed_refusal() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({ "reason": SEAL_FAILED_REFUSAL_REASON }))
        .expect("static refusal shape is always serializable")
}

/// `compute_attestation.agent_input_digest` / `agent_output_digest` off a
/// received foreign capsule body -- carried onto the citing record so the
/// pane's digest-first `exchange_key_for` correlator can group it with this
/// node's own half of the same exchange. `None` when the field is absent
/// (never fabricated).
fn foreign_digest<'a>(capsule: &'a serde_json::Value, field: &str) -> Option<&'a str> {
    capsule
        .pointer("/model_attestation/compute_attestation")
        .and_then(|ca| ca.get(field))
        .and_then(|v| v.as_str())
}

async fn bridge_inbound_record_push(
    listener: LocalListener,
    capsules: Arc<CapsuleState>,
) -> anyhow::Result<()> {
    let local = listener.accept().await?;
    let (mut read_half, mut write_half) = local.into_split();

    // BOUNDED read: the wire bytes are peer-controlled and the SDK's frame
    // cap does not apply to raw side-streams -- see
    // `mesh_evidence_bridge::read_to_end_bounded` (remote-OOM guard).
    let wire = crate::mesh_evidence_bridge::read_to_end_bounded(
        &mut read_half,
        "mesh-inbound record-push wire bytes",
    )
    .await?;
    let (sender_peer_id, capsule_bytes) = split_wire(&wire)
        .ok_or_else(|| anyhow::anyhow!("record-push wire bytes carry no sender-peer-id line"))?;
    let sender_peer_id = sender_peer_id.to_string();
    let capsule_bytes = capsule_bytes.to_vec();

    let client = reqwest::Client::builder()
        .timeout(responder_http_timeout())
        .build()?;
    let url = format!("{}/evidence/record-push", evidence_server_url());
    let response = client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("X-Mesh-Requester-Id", &sender_peer_id)
        .body(capsule_bytes.clone())
        .send()
        .await?;
    let response_bytes = response.bytes().await?;

    // SEAL BEFORE ACK (the ack-before-seal window fix): the door is the ONE
    // authority on whether the half verified + stored, and its refusal bytes
    // are still forwarded untouched -- but on door SUCCESS the citing record
    // is sealed FIRST, and only then is the door's success reply written, so
    // "received" always implies "cited". A seal failure replies with this
    // bridge's own refusal (`SEAL_FAILED_REFUSAL_REASON`) instead of the
    // success bytes: the peer sees a refusal and retries, instead of
    // trusting an ack for a half our chain never cited. Awaited inline (no
    // detached task), so a failure is handled before any reply exists.
    let door_reply = serde_json::from_slice::<serde_json::Value>(&response_bytes).ok();
    let reply_bytes = match door_reply {
        Some(reply) if door_accepted(&reply) => {
            match seal_citing_record_for_push(&capsules, &sender_peer_id, &capsule_bytes).await {
                Ok(()) => response_bytes.to_vec(),
                Err(error) => {
                    tracing::warn!(%error, received_from = %sender_peer_id, "door stored the pushed half but the citing-record seal failed -- refusing instead of acking");
                    seal_failed_refusal()
                }
            }
        }
        // Door refusal (or unparseable door reply): forwarded byte-for-byte;
        // a refusal never chains anything.
        _ => response_bytes.to_vec(),
    };
    write_half.write_all(&reply_bytes).await?;
    write_half.shutdown().await?;
    Ok(())
}

/// on door success, seal OUR OWN
/// citing record of the receiving event onto OUR chain. The door already
/// verified the signature (it returns success only when it did) and stored
/// the foreign body in the held-artifact store -- so `signature_ok = true`
/// here is the door's recorded verdict, read, never a second check. This
/// never touches the foreign body except to lift its own digests (for the
/// pane's correlator); the bytes stay in `received-capsules.jsonl`.
///
/// Runs the seal on `spawn_blocking`: `emit_citing_record` holds the std
/// ledger mutex across two `sync_all()`s, which must not stall a tokio
/// worker thread. A duplicate push (already-cited half, `Ok(None)`) is
/// SUCCESS -- the half is received/held; there is just nothing new to cite.
async fn seal_citing_record_for_push(
    capsules: &Arc<CapsuleState>,
    sender_peer_id: &str,
    capsule_bytes: &[u8],
) -> anyhow::Result<()> {
    let foreign: serde_json::Value = serde_json::from_slice(capsule_bytes)
        // The door accepted a body it could not have parsed? It never does
        // (it refuses request_malformed first) -- but if the contract ever
        // changed, we must not ack a half we cannot cite.
        .map_err(|e| anyhow::anyhow!("door accepted an unparseable body: {e}"))?;
    let Some(foreign_capsule_id) = foreign.get("capsule_id").and_then(|v| v.as_str()) else {
        anyhow::bail!("door accepted a body with no capsule_id -- nothing citable");
    };
    let foreign_capsule_id = foreign_capsule_id.to_string();
    let received_from = sender_peer_id.to_string();
    let received_at = capsule_producer::timestamp::utc_now_iso8601();
    let foreign_input = foreign_digest(&foreign, "agent_input_digest").map(str::to_string);
    let foreign_output = foreign_digest(&foreign, "agent_output_digest").map(str::to_string);
    let capsules = capsules.clone();

    let sealed = tokio::task::spawn_blocking(move || {
        let prov = ReceivedHalfProvenance {
            foreign_capsule_id: &foreign_capsule_id,
            received_from: &received_from,
            via: "push",
            received_at: &received_at,
            signature_ok: true,
            // digest_match is the pane's authoritative structural grade
            // (mine vs theirs); at live receive this node has not paired it
            // against a local half here, so it is an honest absent rather
            // than a fabricated "verified". The pane recomputes it from the
            // citing record's digests + our own half.
            digest_match: None,
            foreign_agent_input_digest: foreign_input.as_deref(),
            foreign_agent_output_digest: foreign_output.as_deref(),
        };
        capsules
            .emit_citing_record(&prov)
            .map(|emitted| (foreign_capsule_id, received_from, emitted))
    })
    .await
    .map_err(|join_error| anyhow::anyhow!("citing-record seal task did not complete: {join_error}"))??;

    let (foreign_capsule_id, received_from, emitted) = sealed;
    match emitted {
        Some(_) => {
            tracing::info!(%foreign_capsule_id, %received_from, "SEALED citing record for received counterparty half");
        }
        None => {
            tracing::info!(%foreign_capsule_id, %received_from, "duplicate push of an already-cited half -- received/held, nothing new sealed");
        }
    }
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
        // Bounded: the peer's ack/refusal is peer-controlled bytes too.
        crate::mesh_evidence_bridge::read_to_end_bounded(
            &mut read_half,
            "peer record-push response",
        )
        .await
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
