//! Real interop test for the `evidence-request/1` plugin-mesh-stream carrier
//! (`mesh_evidence_bridge`), over the ACTUAL wire protocol -- same fake-host
//! approach as `tests/interop.rs` (this repo's CI cannot build
//! `mesh-llm-host-runtime`; see that file's header), extended with the two
//! message types `interop.rs` does not need: `OpenStreamRequest` (drives the
//! RESPONDER role, `on_open_stream`) and `RpcRequest{"tools/call"}` +
//! `OpenMeshStreamRequest` (drives the REQUESTER role, the
//! `mesh_evidence_request` tool).
//!
//! The real mesh-llm host gates BOTH of these on `evidence-request/1` being
//! declared before ever reaching this plugin (`plugin_event_channel_declared`,
//! `mesh/plugin_streams.rs`); this fake host sends them directly, exactly as
//! the real host would after that gate already passed -- proving the
//! plugin's OWN behavior once reached, not the host's gate (untestable here
//! without `mesh-llm-host-runtime`; that gate is upstream, unmodified code).

use mesh_llm_plugin::proto::{self, envelope::Payload};
use mesh_llm_plugin::{
    connect_side_stream, read_envelope, write_envelope, LocalListener, LocalStream,
    PROTOCOL_VERSION,
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixListener};
use tokio::process::Command;
use tokio::time::timeout;

const PLUGIN_BIN: &str = env!("CARGO_BIN_EXE_admission-policy-plugin");
const TEST_TIMEOUT: Duration = Duration::from_secs(10);
const EVIDENCE_REQUEST_CHANNEL: &str = "evidence-request/1";

struct Harness {
    child: tokio::process::Child,
    stream: LocalStream,
    next_request_id: u64,
}

impl Harness {
    async fn spawn(extra_env: &[(&str, &str)]) -> Self {
        let socket_path =
            std::env::temp_dir().join(format!("mesh-evidence-interop-{}.sock", nonce()));
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path).expect("bind fake-host socket");

        let mut cmd = Command::new(PLUGIN_BIN);
        cmd.env("MESH_LLM_PLUGIN_ENDPOINT", &socket_path)
            .env("MESH_LLM_PLUGIN_TRANSPORT", "unix")
            .env("ADMISSION_POLICY_BLOCKED_MODELS", "blocked-test-model")
            .env("ADMISSION_POLICY_MESH_REQUEST_TIMEOUT_MS", "1500")
            // `bind_side_stream` (mesh-llm-plugin's own `io.rs`) derives the
            // evidence-stream's local socket path from `std::env::temp_dir()`
            // with no override of its own -- on macOS that resolves to a long
            // per-process `/var/folders/.../T/` path which, combined with
            // this plugin's own prefix, sits right at (or over) `sockaddr_un`'s
            // ~104-byte `sun_path` limit (same class of issue `host_runtime_
            // e2e.rs`'s `RealHost` already works around for `$HOME`-derived
            // plugin socket paths). `/tmp` keeps it well under that limit.
            .env("TMPDIR", "/tmp");
        for (key, value) in extra_env {
            cmd.env(key, value);
        }
        let child = cmd.spawn().expect("spawn admission-policy-plugin");

        let stream = timeout(
            TEST_TIMEOUT,
            LocalListener::Unix(listener, socket_path).accept(),
        )
        .await
        .expect("plugin connected before timeout")
        .expect("accept plugin connection");

        Self {
            child,
            stream,
            next_request_id: 1,
        }
    }

    fn next_id(&mut self) -> u64 {
        let id = self.next_request_id;
        self.next_request_id += 1;
        id
    }

    async fn send(&mut self, payload: Payload) -> u64 {
        let request_id = self.next_id();
        write_envelope(
            &mut self.stream,
            &proto::Envelope {
                protocol_version: PROTOCOL_VERSION,
                plugin_id: "admission-policy".to_string(),
                request_id,
                payload: Some(payload),
            },
        )
        .await
        .expect("write envelope to plugin");
        request_id
    }

    async fn recv(&mut self) -> proto::Envelope {
        timeout(TEST_TIMEOUT, read_envelope(&mut self.stream))
            .await
            .expect("plugin responded before timeout")
            .expect("read envelope from plugin")
    }

    async fn initialize(&mut self) {
        let request_id = self
            .send(Payload::InitializeRequest(proto::InitializeRequest {
                host_protocol_version: PROTOCOL_VERSION,
                host_version: "mesh-evidence-interop-test".to_string(),
                host_info_json: "{}".to_string(),
                mesh_visibility: proto::MeshVisibility::Private as i32,
            }))
            .await;
        let envelope = self.recv().await;
        assert_eq!(envelope.request_id, request_id);
        let response = match envelope.payload {
            Some(Payload::InitializeResponse(response)) => response,
            other => panic!("expected InitializeResponse, got {other:?}"),
        };
        let manifest = response.manifest.expect("plugin declares a manifest");
        assert!(
            manifest
                .mesh_channels
                .iter()
                .any(|channel| channel.name == EVIDENCE_REQUEST_CHANNEL),
            "manifest must declare {EVIDENCE_REQUEST_CHANNEL}: {manifest:?}"
        );
    }

    /// Responder-role driver: send `OpenStreamRequest` directly (the real
    /// host only ever does this once `evidence-request/1` is already
    /// gate-checked -- see module docs), dial the returned endpoint as the
    /// real host's `bridge_local_stream_bidirectional` would, and return a
    /// connected duplex stream standing in for the remote peer's QUIC bytes.
    async fn open_evidence_stream(&mut self) -> LocalStream {
        let request_id = self
            .send(Payload::OpenStreamRequest(proto::OpenStreamRequest {
                stream_id: format!("test-stream-{}", nonce()),
                purpose: proto::StreamPurpose::Generic as i32,
                mode: proto::StreamMode::RawBytes as i32,
                bidirectional: true,
                content_type: Some("application/json".to_string()),
                correlation_id: None,
                metadata_json: None,
                expected_bytes: None,
                idle_timeout_ms: None,
            }))
            .await;
        let envelope = self.recv().await;
        assert_eq!(envelope.request_id, request_id);
        let response = match envelope.payload {
            Some(Payload::OpenStreamResponse(response)) => response,
            other => panic!("expected OpenStreamResponse, got {other:?}"),
        };
        assert!(response.accepted, "plugin must accept the evidence stream");
        let endpoint = response.endpoint.expect("accepted response carries an endpoint");
        connect_side_stream(&endpoint, response.transport_kind)
            .await
            .expect("dial the plugin's local listener")
    }

    /// Requester-role driver: send the `mesh_evidence_request` tool call,
    /// then service exactly ONE outbound `OpenMeshStreamRequest` the way the
    /// real host's `open_outbound_plugin_mesh_stream` would (accept + reply),
    /// via `respond_open_mesh_stream`, before reading the tool's
    /// `RpcResponse`. Returns the raw envelope so both the success and
    /// error (`ErrorResponse`) shapes are inspectable.
    async fn call_mesh_evidence_tool(
        &mut self,
        peer_id: &str,
        request: serde_json::Value,
        respond_open_mesh_stream: impl FnOnce(proto::OpenMeshStreamRequest) -> proto::OpenMeshStreamResponse,
    ) -> proto::Envelope {
        let params_json = serde_json::json!({
            "name": "mesh_evidence_request",
            "arguments": {"peer_id": peer_id, "request": request},
        })
        .to_string();
        let call_request_id = self
            .send(Payload::RpcRequest(proto::RpcRequest {
                method: "tools/call".to_string(),
                params_json,
            }))
            .await;

        let mesh_stream_envelope = self.recv().await;
        let mesh_stream_request = match mesh_stream_envelope.payload {
            Some(Payload::OpenMeshStreamRequest(request)) => request,
            other => panic!("expected outbound OpenMeshStreamRequest, got {other:?}"),
        };
        assert_eq!(mesh_stream_request.channel, EVIDENCE_REQUEST_CHANNEL);
        assert_eq!(mesh_stream_request.target_peer_id, peer_id);
        let mesh_stream_response = respond_open_mesh_stream(mesh_stream_request);
        write_envelope(
            &mut self.stream,
            &proto::Envelope {
                protocol_version: PROTOCOL_VERSION,
                plugin_id: "admission-policy".to_string(),
                request_id: mesh_stream_envelope.request_id,
                payload: Some(Payload::OpenMeshStreamResponse(mesh_stream_response)),
            },
        )
        .await
        .expect("write OpenMeshStreamResponse to plugin");

        let response_envelope = self.recv().await;
        assert_eq!(response_envelope.request_id, call_request_id);
        response_envelope
    }
}

fn nonce() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    format!(
        "{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

/// Stands in for the remote peer that the fake host's `respond_open_mesh_
/// stream` reports as reachable: binds a real local listener and accepts
/// exactly one connection, playing "the peer's own responder". A Unix
/// socket, not TCP -- `mesh-llm-plugin`'s own `connect_side_stream` (what
/// `PluginContext::connect_mesh_stream` dials with) only implements
/// `StreamTransportKind::StreamUnixSocket`/`StreamNamedPipe`; `StreamTcp` is
/// a `#[cfg(test)]`-only variant internal to the real host, never dialable
/// from plugin-side code.
async fn accept_one_remote_peer_connection() -> (UnixListener, std::path::PathBuf) {
    let path = std::env::temp_dir().join(format!("mesh-evidence-fake-peer-{}.sock", nonce()));
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).expect("bind fake peer");
    (listener, path)
}

/// A minimal local HTTP server standing in for `evidence_server.py`: always
/// answers `POST /evidence-request` with a canned body, recording every
/// request it received. Proves the RESPONDER role's proxy plumbing
/// (mesh bytes in -> real HTTP POST out -> HTTP body back as mesh bytes)
/// without depending on a Python process from a Rust test -- `evidence_
/// responder.answer()`'s own correctness is proven in `tests/test_ask_
/// history.py` and friends, unchanged and untouched by this carrier.
async fn spawn_fake_evidence_server(
    response_body: &'static [u8],
) -> (String, std::sync::Arc<tokio::sync::Mutex<Vec<Vec<u8>>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind fake evidence_server.py");
    let port = listener.local_addr().unwrap().port();
    let received = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let received_for_task = received.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let received = received_for_task.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                let read = socket.read(&mut buf).await.unwrap_or(0);
                let request = &buf[..read];
                let header_end = request
                    .windows(4)
                    .position(|w| w == b"\r\n\r\n")
                    .map(|i| i + 4)
                    .unwrap_or(request.len());
                received.lock().await.push(request[header_end..].to_vec());

                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                    response_body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.write_all(response_body).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    (format!("http://127.0.0.1:{port}"), received)
}

/// (A) Responder role, happy path: a mesh-inbound evidence-request stream
/// gets bridged, byte for byte, to a real local HTTP POST against the
/// configured `evidence_server.py` door, and the door's response comes back
/// unaltered over the same stream.
#[tokio::test]
async fn responder_bridges_inbound_stream_to_local_evidence_door() {
    let refusal = br#"{"reason":"no_such_record","request_digest":"a","issued_at":"b","key_id":"c","sig":"d"}"#;
    let (evidence_server_url, received) = spawn_fake_evidence_server(refusal).await;

    let mut harness = Harness::spawn(&[(
        "ADMISSION_POLICY_EVIDENCE_SERVER_URL",
        &evidence_server_url,
    )])
    .await;
    harness.initialize().await;

    let stream = harness.open_evidence_stream().await;
    let (mut read_half, mut write_half) = stream.into_split();
    let request_bytes = br#"{"subject":{"kind":"record","capsule_id":"ff"}}"#;
    write_half.write_all(request_bytes).await.expect("write E14 request");
    write_half.shutdown().await.expect("half-close request");

    let mut response_bytes = Vec::new();
    timeout(TEST_TIMEOUT, read_half.read_to_end(&mut response_bytes))
        .await
        .expect("responder answered before timeout")
        .expect("read response bytes");

    assert_eq!(response_bytes, refusal);
    assert_eq!(received.lock().await.as_slice(), &[request_bytes.to_vec()]);

    harness.shutdown_process().await;
}

/// (B) Requester role, happy path: the `mesh_evidence_request` tool opens a
/// real outbound `OpenMeshStreamRequest`, writes the E14 request over the
/// resulting stream, and returns the peer's raw response bytes as the tool's
/// JSON result -- proven against a REAL dialed connection playing the remote
/// peer, not a stub.
#[tokio::test]
async fn requester_tool_call_round_trips_a_real_dialed_stream() {
    let mut harness = Harness::spawn(&[]).await;
    harness.initialize().await;

    let (peer_listener, peer_path) = accept_one_remote_peer_connection().await;
    let peer_task = tokio::spawn(async move {
        let (mut socket, _) = peer_listener.accept().await.expect("accept from requester");
        let mut request_bytes = Vec::new();
        socket
            .read_to_end(&mut request_bytes)
            .await
            .expect("read E14 request from requester");
        let response = br#"{"subject_kind":"record","bundles":[]}"#;
        socket.write_all(response).await.expect("write response");
        socket.shutdown().await.expect("half-close response");
        request_bytes
    });

    let request = serde_json::json!({"subject": {"kind": "record", "capsule_id": "aa"}});
    let response_envelope = harness
        .call_mesh_evidence_tool("aa".repeat(32).as_str(), request.clone(), |_request| {
            proto::OpenMeshStreamResponse {
                stream_id: "test".to_string(),
                accepted: true,
                transport_kind: proto::StreamTransportKind::StreamUnixSocket as i32,
                endpoint: Some(peer_path.to_str().unwrap().to_string()),
                token: None,
                expires_at_unix_ms: None,
                message: None,
            }
        })
        .await;

    let result = match response_envelope.payload {
        Some(Payload::RpcResponse(response)) => response,
        other => panic!("expected a successful RpcResponse, got {other:?}"),
    };
    let call_result: rmcp::model::CallToolResult =
        serde_json::from_str(&result.result_json).expect("decode CallToolResult");
    assert_eq!(call_result.is_error, Some(false));
    let structured = call_result
        .structured_content
        .expect("mesh_evidence_request returns structured JSON");
    assert_eq!(structured["subject_kind"], "record");

    let request_bytes = timeout(TEST_TIMEOUT, peer_task)
        .await
        .expect("peer task finished")
        .expect("peer task did not panic");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&request_bytes).unwrap(),
        request
    );

    harness.shutdown_process().await;
}

/// (C) Clean failure, never a hang: a peer that never declares the channel
/// has its stream dropped by the real host with no reply
/// (`handle_plugin_mesh_stream` returns `Ok(())` without touching `send`/
/// `recv` -- see module docs) -- simulated here by the fake host accepting
/// the mesh-stream open but never dialing/writing anything back. Bounded by
/// `ADMISSION_POLICY_MESH_REQUEST_TIMEOUT_MS` (set to 1500ms for this test
/// harness, see `Harness::spawn`), so this test proves the bound, not merely
/// that failure is possible.
#[tokio::test]
async fn requester_reports_a_clean_failure_when_the_peer_never_answers() {
    let mut harness = Harness::spawn(&[]).await;
    harness.initialize().await;

    let (peer_listener, peer_path) = accept_one_remote_peer_connection().await;
    // Never accept the connection the plugin dials -- exactly what "the real
    // peer's host silently drops the stream" looks like from here.
    std::mem::forget(peer_listener);

    let started = tokio::time::Instant::now();
    let response_envelope = harness
        .call_mesh_evidence_tool("bb".repeat(32).as_str(), serde_json::json!({}), |_request| {
            proto::OpenMeshStreamResponse {
                stream_id: "test".to_string(),
                accepted: true,
                transport_kind: proto::StreamTransportKind::StreamUnixSocket as i32,
                endpoint: Some(peer_path.to_str().unwrap().to_string()),
                token: None,
                expires_at_unix_ms: None,
                message: None,
            }
        })
        .await;
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_secs(5),
        "requester must fail within its bounded timeout, took {elapsed:?}"
    );
    match response_envelope.payload {
        Some(Payload::ErrorResponse(_)) => {}
        other => panic!("expected a bounded ErrorResponse, got {other:?} after {elapsed:?}"),
    }

    harness.shutdown_process().await;
}

/// (D) Mutant: tamper the bytes the peer writes back, in flight, before the
/// requester ever sees them -- proves the carrier does not itself validate
/// or silently repair anything; that job stays with the caller's own
/// offline verify (`ask_history.py`'s `verify_bundle`/`verify_refusal_
/// offline`, unchanged and exercised in `tests/test_ask_history.py`).
#[tokio::test]
async fn tampered_bytes_in_flight_pass_through_unvalidated_and_unrepaired() {
    let mut harness = Harness::spawn(&[]).await;
    harness.initialize().await;

    let (peer_listener, peer_path) = accept_one_remote_peer_connection().await;
    let genuine = br#"{"subject_kind":"record","bundles":[{"receipt":{"capsule_id":"real"}}]}"#.to_vec();
    let mut tampered = genuine.clone();
    let flip_at = tampered.iter().position(|&b| b == b'r').expect("has a byte to flip");
    tampered[flip_at] = b'X';
    let tampered_for_task = tampered.clone();
    tokio::spawn(async move {
        let (mut socket, _) = peer_listener.accept().await.expect("accept from requester");
        let mut discard = Vec::new();
        let _ = socket.read_to_end(&mut discard).await;
        let _ = socket.write_all(&tampered_for_task).await;
        let _ = socket.shutdown().await;
    });

    let response_envelope = harness
        .call_mesh_evidence_tool("cc".repeat(32).as_str(), serde_json::json!({}), |_request| {
            proto::OpenMeshStreamResponse {
                stream_id: "test".to_string(),
                accepted: true,
                transport_kind: proto::StreamTransportKind::StreamUnixSocket as i32,
                endpoint: Some(peer_path.to_str().unwrap().to_string()),
                token: None,
                expires_at_unix_ms: None,
                message: None,
            }
        })
        .await;

    let result = match response_envelope.payload {
        Some(Payload::RpcResponse(response)) => response,
        other => panic!("expected a successful (carrier-level) RpcResponse, got {other:?}"),
    };
    let call_result: rmcp::model::CallToolResult =
        serde_json::from_str(&result.result_json).expect("decode CallToolResult");
    let structured = call_result.structured_content.expect("structured JSON");
    let round_tripped = serde_json::to_vec(&structured).expect("re-encode");

    // The carrier delivered the TAMPERED bytes untouched -- it neither
    // detected nor repaired the flip. (Confirming that a flip THIS SHAPED is
    // rejected downstream is `test_tamper_check_detects_a_flipped_byte` in
    // `tests/test_ask_history.py` -- a carrier-independent property of
    // `verify_bundle`, deliberately not re-proven here.)
    assert_ne!(round_tripped, genuine, "the tampered byte must reach the caller");

    harness.shutdown_process().await;
}

impl Harness {
    async fn shutdown_process(mut self) {
        let request_id = self
            .send(Payload::ShutdownRequest(proto::ShutdownRequest {
                reason: "mesh evidence bridge interop test complete".to_string(),
            }))
            .await;
        let envelope = self.recv().await;
        assert_eq!(envelope.request_id, request_id);
        assert!(matches!(
            envelope.payload,
            Some(Payload::ShutdownResponse(_))
        ));

        let status = timeout(TEST_TIMEOUT, self.child.wait())
            .await
            .expect("plugin exited before timeout")
            .expect("wait on plugin process");
        assert!(status.success(), "plugin process exited with {status:?}");
    }
}
