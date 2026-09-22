//! `ledger-fetch/1`: the plugin-mesh-stream carrier for the E9/E10 two-sided
//! ledger's "evidence-door fetch" -- on demand, off the request hot path, a
//! peer reads back ONE of THIS node's own sealed ledger entries by
//! `capsule_id` (the join key `lifecycle_channel::peer_capsule_id_for_seal`
//! already threads onto the requester's own sealed row). Modeled directly on
//! `mesh_evidence_bridge`'s responder/requester shape -- same
//! `OpenMeshStreamRequest`/`connect_mesh_stream` mechanism, zero new
//! mesh-llm-host-runtime protocol code -- but answers from
//! `CapsuleState::lookup` instead of proxying to `evidence_server.py`: this
//! door carries no E14/E15 Bundle semantics and no checkpoint-coverage
//! requirement (`capsule_emit.bundle.py`'s `BundleError` gate does not apply
//! here), so a capsule sealed seconds ago is fetchable immediately.
//!
//! **Witness-level recompute only, never a second attestation.** The
//! responder returns the raw, *unsigned* `{capsule, signed_statement_b64,
//! node_pub_key_pem}` for a found entry -- nothing here signs, endorses, or
//! judges it. The requester (and, upstream, the browser's own
//! `recompute-identity.ts`) independently recomputes and verifies; this
//! bridge only carries bytes.
//!
//! **Sharing the plugin's one `on_open_stream` slot.** `DeclarativePluginBuilder`
//! keeps a single responder-side stream handler, and `OpenStreamRequest` (the
//! shape actually delivered to it) carries no channel name -- the mesh host
//! resolves channel gating before the plugin ever sees the request. `main.rs`
//! tells the two carriers apart by `OpenStreamRequest.metadata_json`: this
//! module's requester tags its open with `LEDGER_FETCH_METADATA_TAG`;
//! `mesh_evidence_bridge`'s requester always sends `None`. Anything other
//! than the exact tag falls through to the evidence-request path, so this is
//! purely additive -- no existing behavior changes.
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use mesh_llm_plugin::proto::{OpenMeshStreamRequest, OpenStreamRequest, OpenStreamResponse};
use mesh_llm_plugin::{
    bind_side_stream, LocalListener, LocalStream, PluginContext, PluginError, PluginResult,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::capsule_emit::CapsuleState;
use crate::mesh_evidence_bridge::{env_millis, next_stream_id};

/// The mesh channel this plugin declares on both ends, alongside
/// `mesh_evidence_bridge::EVIDENCE_REQUEST_CHANNEL`.
pub const LEDGER_FETCH_CHANNEL: &str = "ledger-fetch/1";

/// The tool name the requester side calls locally
/// (`POST /api/plugins/<plugin_id>/tools/mesh_ledger_fetch`).
pub const LEDGER_FETCH_OPERATION: &str = "mesh_ledger_fetch";

/// Tags an outbound `OpenMeshStreamRequest.metadata_json` as a ledger-fetch
/// open -- see module doc for why this, and not the channel name, is what
/// `main.rs`'s shared `on_open_stream` handler dispatches on.
const LEDGER_FETCH_METADATA_TAG: &str = "ledger-fetch/1";

/// True exactly when an inbound `OpenStreamRequest` is this module's; the
/// requester below is the only code in this plugin that ever sets this tag.
pub fn is_ledger_fetch_request(request: &OpenStreamRequest) -> bool {
    request.metadata_json.as_deref() == Some(LEDGER_FETCH_METADATA_TAG)
}

/// How long the RESPONDER waits for the mesh stream to actually deliver a
/// request (and separately, once it has one, to write the reply) before
/// giving up -- bounds a peer that opens the stream and then goes silent.
/// Overridable so a test proving the bound is enforced does not have to wait
/// out the production default.
fn responder_timeout() -> Duration {
    env_millis("ADMISSION_POLICY_LEDGER_FETCH_HTTP_TIMEOUT_MS", 10_000)
}

/// How long the REQUESTER waits for a response once the mesh stream is open
/// -- mirrors `mesh_evidence_bridge::requester_idle_timeout_ms`'s contract:
/// a peer that never declared the channel has its stream dropped by the host
/// with no reply, and this bound turns that into a clean failure, not a hang.
fn requester_idle_timeout_ms() -> u64 {
    env_millis("ADMISSION_POLICY_LEDGER_FETCH_TIMEOUT_MS", 8_000).as_millis() as u64
}

// ---------------------------------------------------------------------
// Responder role: mesh-inbound `ledger-fetch/1` stream -> local ledger lookup
// ---------------------------------------------------------------------

/// Registered (via `main.rs`'s shared dispatcher) as the ledger-fetch half
/// of this plugin's `on_open_stream` handler. Never fabricates a capsule --
/// a lookup miss or a malformed request both produce an honest, explicit
/// response variant (see [`LedgerFetchResponse`]); only a real
/// `CapsuleState::lookup` hit ever carries capsule bytes.
pub async fn handle_open_stream(
    request: OpenStreamRequest,
    _context: &mut PluginContext<'_>,
    capsules: Arc<CapsuleState>,
) -> PluginResult<Option<OpenStreamResponse>> {
    let listener = bind_side_stream(crate::PLUGIN_ID, &request.stream_id)
        .await
        .map_err(|error| PluginError::internal(error.to_string()))?;
    let response = listener.open_stream_response(&request);

    tokio::spawn(async move {
        if let Err(error) = bridge_inbound_ledger_fetch_stream(listener, capsules).await {
            tracing::warn!(%error, "mesh ledger-fetch responder bridge failed");
        }
    });

    Ok(Some(response))
}

#[derive(Debug, Deserialize)]
struct LedgerFetchRequest {
    capsule_id: String,
}

/// Every shape the responder can answer with -- deliberately explicit rather
/// than a bare `Option`/error string, so a caller (and a test) can tell
/// "no such entry" from "your request was malformed" from "here are the
/// bytes" without guessing at string contents.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "status", rename_all = "snake_case")]
enum LedgerFetchResponse {
    Found {
        capsule: Value,
        /// Raw COSE_Sign1 bytes, base64-standard-encoded for the JSON
        /// carrier -- the same bytes `Ledger::lookup` returns, untouched.
        signed_statement_b64: String,
        node_pub_key_pem: String,
    },
    NotFound {
        capsule_id: String,
    },
    Error {
        message: String,
    },
}

async fn bridge_inbound_ledger_fetch_stream(
    listener: LocalListener,
    capsules: Arc<CapsuleState>,
) -> anyhow::Result<()> {
    let local = tokio::time::timeout(responder_timeout(), listener.accept()).await??;
    let (mut read_half, mut write_half) = local.into_split();

    // The requester writes the whole `{"capsule_id": ...}` request then
    // half-closes (same convention `mesh_evidence_bridge` uses) -- read to
    // EOF to get exactly the request bytes.
    let mut request_bytes = Vec::new();
    tokio::time::timeout(
        responder_timeout(),
        read_half.read_to_end(&mut request_bytes),
    )
    .await??;

    let response = answer(&capsules, &request_bytes);

    let response_bytes = serde_json::to_vec(&response)?;
    tokio::time::timeout(responder_timeout(), async {
        write_half.write_all(&response_bytes).await?;
        write_half.shutdown().await
    })
    .await??;
    Ok(())
}

/// The pure lookup-to-response step, split out of the async I/O wrapper so
/// it is directly unit-testable (found / not-found / malformed) without a
/// live mesh stream.
fn answer(capsules: &CapsuleState, request_bytes: &[u8]) -> LedgerFetchResponse {
    let parsed = match serde_json::from_slice::<LedgerFetchRequest>(request_bytes) {
        Ok(parsed) => parsed,
        Err(error) => {
            return LedgerFetchResponse::Error {
                message: format!("malformed ledger-fetch request: {error}"),
            }
        }
    };

    match capsules.lookup(&parsed.capsule_id) {
        Ok(Some(entry)) => LedgerFetchResponse::Found {
            capsule: entry.capsule,
            signed_statement_b64: base64::engine::general_purpose::STANDARD
                .encode(&entry.signed_statement),
            node_pub_key_pem: capsules.public_key_pem(),
        },
        Ok(None) => LedgerFetchResponse::NotFound {
            capsule_id: parsed.capsule_id,
        },
        Err(error) => LedgerFetchResponse::Error {
            message: format!("ledger lookup failed: {error}"),
        },
    }
}

// ---------------------------------------------------------------------
// Requester role: local tool call -> outbound `ledger-fetch/1` stream
// ---------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct MeshLedgerFetchArgs {
    /// Hex-encoded mesh peer id whose ledger to fetch from, e.g.
    /// `iroh::EndpointId::to_string()`.
    pub peer_id: String,
    /// The peer-asserted `capsule_id` to fetch -- the join key piece 1
    /// (`lifecycle_channel::peer_capsule_id_for_seal`) threads onto this
    /// node's own sealed row for a `RemoteMesh` exchange.
    pub capsule_id: String,
}

/// Registered as the `mesh_ledger_fetch` tool/operation handler. Returns the
/// peer's raw `LedgerFetchResponse` JSON unchanged on success; any transport
/// failure (unroutable peer, channel undeclared on the peer, response never
/// arrives) surfaces as a tool error, which the host's `/tools/` HTTP route
/// reports as a `502`, never a hang.
pub async fn handle_mesh_ledger_fetch(
    args: MeshLedgerFetchArgs,
    context: &mut PluginContext<'_>,
) -> PluginResult<Value> {
    if args.peer_id.trim().is_empty() {
        return Err(PluginError::invalid_params("peer_id must not be empty"));
    }
    if args.capsule_id.trim().is_empty() {
        return Err(PluginError::invalid_params("capsule_id must not be empty"));
    }

    let open_request = OpenMeshStreamRequest {
        stream_id: next_stream_id("ledger-fetch"),
        target_peer_id: args.peer_id.clone(),
        plugin_id: String::new(), // host fills this in from the connection.
        channel: LEDGER_FETCH_CHANNEL.to_string(),
        purpose: mesh_llm_plugin::proto::StreamPurpose::Generic as i32,
        mode: mesh_llm_plugin::proto::StreamMode::RawBytes as i32,
        bidirectional: true,
        content_type: Some("application/json".to_string()),
        correlation_id: Some(next_stream_id("ledger-fetch-correlation")),
        metadata_json: Some(LEDGER_FETCH_METADATA_TAG.to_string()),
        expected_bytes: None,
        idle_timeout_ms: Some(requester_idle_timeout_ms()),
    };

    let stream: LocalStream = context
        .connect_mesh_stream(open_request)
        .await
        .map_err(|error| PluginError::internal(format!("could not reach peer: {error}")))?;
    let (mut read_half, mut write_half) = stream.into_split();

    let request_bytes = serde_json::to_vec(&serde_json::json!({ "capsule_id": args.capsule_id }))
        .expect("a two-field static-shape object always serializes");

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
    .map_err(|_| PluginError::internal("peer does not answer ledger-fetch requests"))?
    .map_err(|error| {
        PluginError::internal(format!(
            "peer does not answer ledger-fetch requests: {error}"
        ))
    })?;

    serde_json::from_slice(&response_bytes).map_err(|error| {
        PluginError::internal(format!(
            "peer returned malformed ledger-fetch response: {error}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capsule_emit::ExchangeRecord;

    /// Same convention `capsule_emit`'s own tests use -- a process-id-suffixed
    /// dir under the OS temp root, wiped before open -- rather than adding a
    /// `tempfile` dependency for one test module.
    fn open_state(label: &str) -> CapsuleState {
        let dir = std::env::temp_dir().join(format!("ledger-fetch-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        CapsuleState::open(&dir, "ledger-fetch-test").expect("open capsule state")
    }

    fn seal_one(state: &CapsuleState) -> String {
        let emitted = state
            .emit_for_exchange(&ExchangeRecord {
                model: "test-model",
                client_nonce: None,
                request_bytes: b"{}",
                response_bytes: b"{}",
                latency_ms: 1.0,
                exchange_id: Some("exchange-1"),
                requesting_party: None,
                host_provenance: None,
            })
            .expect("seal one capsule");
        emitted.capsule_id
    }

    /// (positive) A real hit round-trips the exact capsule bytes and this
    /// node's real pubkey -- proves the responder answers from the ledger,
    /// not from thin air.
    #[test]
    fn found_entry_carries_the_real_capsule_and_pubkey() {
        let state = open_state("found");
        let capsule_id = seal_one(&state);

        let request = serde_json::to_vec(&serde_json::json!({ "capsule_id": capsule_id })).unwrap();
        let response = answer(&state, &request);

        match response {
            LedgerFetchResponse::Found {
                capsule,
                signed_statement_b64,
                node_pub_key_pem,
            } => {
                assert_eq!(capsule["capsule_id"], capsule_id);
                assert!(!signed_statement_b64.is_empty());
                assert_eq!(node_pub_key_pem, state.public_key_pem());
            }
            other => panic!("expected Found, got {other:?}"),
        }
    }

    /// (negative, R4 other half) A capsule_id this node never sealed must
    /// come back `NotFound`, never a fabricated/empty `Found`.
    #[test]
    fn unknown_capsule_id_is_reported_not_found_never_fabricated() {
        let state = open_state("not-found");
        seal_one(&state); // ledger is non-empty, but the id below is not in it.

        let request =
            serde_json::to_vec(&serde_json::json!({ "capsule_id": "not-a-real-id" })).unwrap();
        let response = answer(&state, &request);

        assert_eq!(
            response,
            LedgerFetchResponse::NotFound {
                capsule_id: "not-a-real-id".to_string()
            }
        );
    }

    /// (negative) Malformed request bytes must produce an explicit `Error`,
    /// never be mistaken for a `NotFound` (which would look like "the ledger
    /// doesn't have anything with this key" instead of "your request was
    /// unreadable").
    #[test]
    fn malformed_request_bytes_are_reported_as_error_not_not_found() {
        let state = open_state("malformed");

        let response = answer(&state, b"not json at all");

        match response {
            LedgerFetchResponse::Error { message } => {
                assert!(message.contains("malformed"), "message was: {message}");
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    /// (positive) `is_ledger_fetch_request` is what `main.rs`'s shared
    /// `on_open_stream` dispatcher relies on to route inbound streams to
    /// this module instead of `mesh_evidence_bridge` -- prove the tag it
    /// checks is exactly the tag the requester above actually sends.
    #[test]
    fn dispatch_tag_matches_the_requesters_own_metadata_json() {
        let tagged = OpenStreamRequest {
            stream_id: "s".to_string(),
            purpose: mesh_llm_plugin::proto::StreamPurpose::Generic as i32,
            mode: mesh_llm_plugin::proto::StreamMode::RawBytes as i32,
            bidirectional: true,
            content_type: None,
            correlation_id: None,
            metadata_json: Some(LEDGER_FETCH_METADATA_TAG.to_string()),
            expected_bytes: None,
            idle_timeout_ms: None,
        };
        assert!(is_ledger_fetch_request(&tagged));
    }

    /// (negative, R4 other half) The evidence-request carrier's own
    /// `metadata_json: None` open (and any other untagged open) must NOT be
    /// claimed by this module -- otherwise every existing evidence-request
    /// stream would silently misroute into the ledger-fetch responder.
    #[test]
    fn untagged_or_differently_tagged_requests_are_never_claimed() {
        let untagged = OpenStreamRequest {
            stream_id: "s".to_string(),
            purpose: mesh_llm_plugin::proto::StreamPurpose::Generic as i32,
            mode: mesh_llm_plugin::proto::StreamMode::RawBytes as i32,
            bidirectional: true,
            content_type: None,
            correlation_id: None,
            metadata_json: None,
            expected_bytes: None,
            idle_timeout_ms: None,
        };
        assert!(!is_ledger_fetch_request(&untagged));

        let mut other_tag = untagged;
        other_tag.metadata_json = Some("some-other-carrier/1".to_string());
        assert!(!is_ledger_fetch_request(&other_tag));
    }
}
