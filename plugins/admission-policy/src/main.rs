mod capsule_emit;
mod checkpoint_cadence;
mod decision;
mod lifecycle_channel;
mod mesh_evidence_bridge;
mod record_push_bridge;
mod self_peer;
/// Not wired into `on_mesh_event` yet -- see the module doc for why
/// (`mesh-llm-plugin = "0.75"` predates the `checkpoint` field this needs to
/// read off `event.peer`). Exercised entirely by its own unit tests today;
/// kept as the tested, ready-to-wire reconciliation logic for when the
/// dependency bumps.
#[allow(dead_code)]
mod peer_root_ledger;
mod share_policy;
mod web_ui_manifest;

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
    peer_capsule_id_for_seal, HostServingProvenance, MirrorUsage, ObservedLifecycleEvents,
    OpenAiExchangeEnvelope, OPENAI_EXCHANGE_CHANNEL,
};
use mesh_evidence_bridge::{
    MeshEvidenceRequestArgs, EVIDENCE_REQUEST_CHANNEL, EVIDENCE_REQUEST_OPERATION,
};
use mesh_llm_plugin::{
    capability, events, inference, json_schema_operation, mesh_channel, plugin_server_info,
    DeclarativePluginBuilder, OperationRouter, PluginMetadata, PluginRuntime,
};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpListener;

const PLUGIN_ID: &str = "capsule-emit-mesh";
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

/// The counterparty peer id for a push-at-completion, when this node can
/// truthfully name one -- whoever sealed the other half of this exchange:
///
/// - A `RemoteMesh` terminal (this node routed the exchange TO a peer): the
///   node that served it, the host's `served_by_node_id`.
/// - A host-served terminal (this node SERVED a peer's request): the node that
///   asked, `requested_by_node_id` -- set by the host only for a request that
///   came over the mesh tunnel, from the tunnel's authenticated remote id.
///   A request that reached this node's local API has no requesting mesh
///   node, so nothing is pushed.
///
/// `None` rather than a guess whenever the host did not name one.
fn push_counterparty(envelope: &OpenAiExchangeEnvelope) -> Option<&str> {
    let provenance = envelope.serving_provenance.as_ref()?;
    let counterparty = if envelope.dispatch_path == lifecycle_channel::DispatchPath::RemoteMesh {
        provenance.served_by_node_id.as_deref()
    } else if ObservedLifecycleEvents::is_sealable_host_served(envelope) {
        provenance.requested_by_node_id.as_deref()
    } else {
        None
    };
    counterparty.filter(|id| !id.is_empty() && *id != "unknown")
}

#[derive(Clone)]
struct AppState {
    models: Arc<Vec<String>>,
    capsules: Arc<CapsuleState>,
    /// The host serving-provenance the plugin has observed on the
    /// `openai.exchange.v1` channel, so the seal path can read the host's real
    /// quantization/hardware/model-digest for the served model.
    lifecycle_events: Arc<ObservedLifecycleEvents>,
    /// This node's latest self-produced checkpoint head, if the checkpoint
    /// cadence task is enabled (`checkpoint_cadence::is_enabled`) --
    /// `[mesh-checkpoint-head-source]`'s sending half reads this to feed
    /// `PeerAnnouncement.checkpoint`. On by default; `None` when the
    /// operator has opted out (`ADMISSION_POLICY_CHECKPOINT_CADENCE=off`)
    /// or hasn't produced a checkpoint since startup.
    #[allow(dead_code)]
    checkpoint_head: Option<checkpoint_cadence::LatestHead>,
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
        weights_digest: observed.weights_digest,
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
///
/// Returns the emitted capsule's own JSON on success, `None` on a producer
/// error -- Seam A1's push-at-completion call
/// site needs the just-sealed capsule's bytes to push; every other existing
/// caller of this function predates that need and only used the side effect,
/// so returning the value here is additive, not a behavior change for them.
fn seal_observed_host_exchange(capsules: &CapsuleState, envelope: &OpenAiExchangeEnvelope) -> Option<Value> {
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
        dispatch_path: envelope.dispatch_path.clone(),
        nonce: envelope.nonce.as_deref(),
        // See `lifecycle_channel::peer_capsule_id_for_seal`'s doc for why
        // this is never a raw `envelope.capsule_id.as_deref()` -- a
        // `SelfMinted` value must never be surfaced as a peer's claim.
        peer_capsule_id: peer_capsule_id_for_seal(envelope).map(|(id, _)| id),
        peer_capsule_id_provenance: peer_capsule_id_for_seal(envelope).map(|(_, prov)| prov),
        twin_bracket_id: envelope.twin_bracket_id.as_deref(),
    };
    match capsules.emit_for_observed_host_exchange(&observed) {
        Ok(emitted) => {
            tracing::info!(
                capsule_id = %emitted.capsule_id,
                model = %envelope.model,
                "SEALED AAC for host-served (observed) exchange"
            );
            Some(emitted.capsule)
        }
        Err(error) => {
            tracing::warn!(
                %error,
                observed_not_sealed = capsules.observed_not_sealed(),
                "failed to seal capsule for observed host-served exchange"
            );
            None
        }
    }
}

/// Seam A1's pure eligibility decision,
/// isolated from the network call so "policy off -> no push" is a real,
/// directly testable mutant, not just a structural early-return no test
/// exercises. `Some((peer_id, self_id))` only when EVERY condition holds:
/// pushing is not turned off, a counterparty is knowable, and this node has
/// a configured self peer id to self-declare. Any missing condition is an
/// honest no-push, never a guess.
fn push_eligibility<'a>(
    envelope: &'a OpenAiExchangeEnvelope,
    record_at_completion_off: bool,
    self_peer_id: Option<&'a str>,
) -> Option<(&'a str, &'a str)> {
    if record_at_completion_off {
        return None;
    }
    let peer_id = push_counterparty(envelope)?;
    let self_id = self_peer_id?;
    Some((peer_id, self_id))
}

/// The counterparty a push would have gone to, when the only thing stopping
/// it is an unknown own peer id -- so the caller can say so instead of
/// skipping silently.
fn skipped_for_missing_self_id<'a>(
    envelope: &'a OpenAiExchangeEnvelope,
    record_at_completion_off: bool,
    self_peer_id: Option<&str>,
) -> Option<&'a str> {
    if record_at_completion_off || self_peer_id.is_some() {
        return None;
    }
    push_counterparty(envelope)
}

/// Seam A1 -- push `capsule_json` (this
/// node's own just-sealed capsule) to `envelope`'s counterparty, when
/// `push_eligibility` says to. Best-effort: logs success/failure, never
/// propagates -- a push failure must not disturb sealing or channel-message
/// processing, same discipline as `seal_observed_host_exchange`'s own
/// producer-error handling.
///
/// Push-a-bundle: with the checkpoint cadence on (`checkpoints` is `Some`),
/// the half goes out with a checkpoint covering it and its inclusion proof,
/// so the receiver reaches "in their log" in one step. If no coverage can be
/// had (cadence off, or a checkpoint-layer error) the bare record is pushed,
/// as before -- the half is never held back for want of a proof.
async fn push_at_completion_if_configured(
    context: &mut mesh_llm_plugin::PluginContext<'_>,
    envelope: &OpenAiExchangeEnvelope,
    capsule_json: Value,
    checkpoints: Option<&checkpoint_cadence::CheckpointHandle>,
    self_peer: &self_peer::SelfPeer,
) {
    // Learned from the host's mesh events (see `self_peer`), unless the
    // operator overrides it. `None` means the host has not reported it yet.
    let self_id = self_peer.current();
    let record_at_completion_off = share_policy::record_at_completion_is_off();
    if let Some(peer_id) =
        skipped_for_missing_self_id(envelope, record_at_completion_off, self_id.as_deref())
    {
        tracing::warn!(
            %peer_id,
            "record-push at completion skipped: this node's own peer id is unknown (the host has not reported it on a mesh event yet and ADMISSION_POLICY_SELF_PEER_ID is unset)"
        );
        return;
    }
    let Some((peer_id, self_id)) =
        push_eligibility(envelope, record_at_completion_off, self_id.as_deref())
    else {
        return;
    };
    let coverage = match (checkpoints, capsule_json.get("capsule_id").and_then(Value::as_str)) {
        (Some(handle), Some(capsule_id)) => match handle.coverage_for(capsule_id).await {
            Ok(coverage) => Some(coverage),
            Err(error) => {
                tracing::warn!(%error, %peer_id, "no checkpoint covering the pushed half -- pushing the bare record");
                None
            }
        },
        _ => None,
    };
    match record_push_bridge::push_capsule_to_peer(
        context,
        peer_id,
        self_id,
        &capsule_json,
        coverage.as_ref(),
    )
    .await
    {
        Ok(()) => {
            tracing::info!(%peer_id, "pushed sealed capsule to counterparty at completion");
        }
        Err(error) => {
            tracing::warn!(%error, %peer_id, "record-push at completion failed");
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

            // Seal on `spawn_blocking`: `emit_for_exchange` holds the std
            // ledger mutex across two `sync_all()`s -- real disk waits that
            // must not stall a tokio worker thread (and, transitively, every
            // other task scheduled on it). The mutex stays std (the
            // sync-fn-holds-lock design is sound); only the CALL moves onto
            // the blocking pool.
            let capsules = state.capsules.clone();
            let model_for_seal = model.clone();
            let exchange_id_for_seal = exchange_id.clone();
            let body_for_seal = body.clone();
            let emit_result = tokio::task::spawn_blocking(move || {
                capsules.emit_for_exchange(&capsule_emit::ExchangeRecord {
                    model: &model_for_seal,
                    client_nonce: client_nonce.as_deref(),
                    request_bytes: &body_for_seal,
                    response_bytes: &response_bytes,
                    latency_ms,
                    exchange_id: Some(&exchange_id_for_seal),
                    // The requesting party beyond the client nonce is not
                    // carried on this direct-serve path — recorded as
                    // "unknown", not invented.
                    requesting_party: None,
                    host_provenance,
                })
            })
            .await;
            match emit_result {
                Ok(Ok(emitted)) => {
                    tracing::info!(capsule_id = %emitted.capsule_id, %model, "emitted AAC for admitted exchange");
                    response["admission_policy"]["capsule_id"] = json!(emitted.capsule_id);
                    response["admission_policy"]["capsule"] = emitted.capsule;
                }
                Ok(Err(error)) => {
                    // Capsule production is best-effort observability, not a
                    // gate: never let a producer bug turn an admitted
                    // exchange into a denied one.
                    tracing::warn!(%error, "failed to emit capsule for admitted exchange");
                }
                Err(join_error) => {
                    // Same best-effort discipline for a panicked/cancelled
                    // seal task: log, never deny the admitted exchange.
                    tracing::warn!(%join_error, "capsule seal task did not complete");
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
    // Packaging time: print the `plugin-manifest.json` the installer reads
    // (config schema + web UI block) and exit, before any listener, ledger,
    // or key is touched.
    if std::env::args().nth(1).as_deref() == Some("--print-package-manifest") {
        println!(
            "{}",
            web_ui_manifest::package_manifest_json_for(
                PLUGIN_ID,
                PLUGIN_VERSION,
                share_policy::share_policy_config_schema(PLUGIN_ID),
            )?
        );
        return Ok(());
    }

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
    let self_peer = self_peer::SelfPeer::new(&data_dir);
    let self_peer_for_events = self_peer.clone();

    // Checkpoint cadence: off by default, node-by-node cutover away from
    // checkpoint_daemon.py -- see checkpoint_cadence.rs's module doc and
    // the Path 1 README note. `checkpoint_shutdown_tx` held for the
    // process lifetime so dropping it doesn't fire the watch early.
    let (checkpoint_shutdown_tx, checkpoint_shutdown_rx) = tokio::sync::watch::channel(false);
    let checkpoints = if checkpoint_cadence::is_enabled() {
        let ledger_dir = data_dir.join("ledger");
        let handle = checkpoint_cadence::spawn(
            ledger_dir,
            PLUGIN_ID.to_string(),
            capsules.signing_key().clone(),
            capsules.clone(),
            checkpoint_shutdown_rx,
        )?;
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            let _ = checkpoint_shutdown_tx.send(true);
        });
        Some(handle)
    } else {
        drop(checkpoint_shutdown_rx);
        None
    };
    let checkpoint_head = checkpoints.as_ref().map(checkpoint_cadence::CheckpointHandle::latest_head);
    let checkpoints_for_handler = checkpoints.clone();

    let capsules_for_handler = capsules.clone();
    // the record-push responder's
    // citing-record seal writes to the SAME single-writer ledger -- one
    // `CapsuleState`, shared by Arc, never a second writer.
    let capsules_for_stream = capsules.clone();
    let app_state = AppState {
        models: Arc::new(models),
        capsules,
        lifecycle_events: lifecycle_events.clone(),
        checkpoint_head,
    };
    tokio::spawn(serve_admission_http(listener, app_state));

    let lifecycle_events_for_handler = lifecycle_events.clone();

    let mut evidence_operations = OperationRouter::new();
    evidence_operations.add_json(
        json_schema_operation::<MeshEvidenceRequestArgs>(
            EVIDENCE_REQUEST_OPERATION,
            "Ask a mesh peer's admission-policy plugin for E15 evidence (an E14 request map) over \
             the plugin mesh stream, for peers with no reachable evidence_server.py HTTP door \
             (e.g. relay-only). Returns the peer's own Artifact-or-Refusal JSON unchanged.",
        ),
        |args, context| Box::pin(mesh_evidence_bridge::handle_mesh_evidence_request(args, context)),
    );

    let plugin = DeclarativePluginBuilder::new(PluginMetadata::new(
        PLUGIN_ID,
        PLUGIN_VERSION,
        plugin_server_info(
            PLUGIN_ID,
            PLUGIN_VERSION,
            "Admission policy",
            "Denies OpenAI-compatible exchanges whose model matches a blocked prefix, and emits a signed chained ledgered AAC for every one it admits.",
            None::<String>,
        ),
    ))
    .provide(capability("admission_policy.v1"))
    .config_item(share_policy::share_policy_config_schema(PLUGIN_ID))
    .web_ui_item(web_ui_manifest::evidence_web_ui())
    .mesh_item(mesh_channel(OPENAI_EXCHANGE_CHANNEL))
    .mesh_item(mesh_channel(EVIDENCE_REQUEST_CHANNEL))
    .mesh_item(mesh_channel(record_push_bridge::RECORD_PUSH_CHANNEL))
    // Any mesh event carries this node's own peer id; the host sends these
    // kinds as a snapshot right after the plugin loads (see `self_peer`).
    .event_item(events::local_accepting())
    .event_item(events::local_standby())
    .event_item(events::mesh_id_updated())
    .event_item(events::peer_up())
    .inference_item(inference::provider(ENDPOINT_ID, address))
    .customize(move |plugin| {
        plugin.on_channel_message(move |message, context| {
            let lifecycle_events = lifecycle_events_for_handler.clone();
            let capsules = capsules_for_handler.clone();
            let checkpoints = checkpoints_for_handler.clone();
            let self_peer = self_peer.clone();
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
                            //
                            // Seal-on-observe, REQUESTER side
                            // (`[mesh-requester-side-seal-on-proxy]`, 2026-09-07):
                            // a `RemoteMesh` terminal event means THIS node
                            // routed the exchange to a peer -- it is the
                            // requester's own half, and until this closed, it
                            // sealed nothing at all. Mutually exclusive with
                            // the host-served branch above (see
                            // `is_sealable_host_served`'s doc comment).
                            if ObservedLifecycleEvents::is_sealable_host_served(&envelope)
                                || ObservedLifecycleEvents::is_sealable_requester_side(&envelope)
                            {
                                // Seal on `spawn_blocking`: the emit path
                                // holds the std ledger mutex across two
                                // `sync_all()`s, which must not stall this
                                // tokio worker (the envelope moves into the
                                // closure and back out, so no clone of the
                                // whole event is needed).
                                let capsules_for_seal = capsules.clone();
                                match tokio::task::spawn_blocking(move || {
                                    let sealed =
                                        seal_observed_host_exchange(&capsules_for_seal, &envelope);
                                    (envelope, sealed)
                                })
                                .await
                                {
                                    Ok((envelope, sealed)) => {
                                        if let Some(capsule_json) = sealed {
                                            // Seam A1:
                                            // push this node's own just-sealed capsule
                                            // to the counterparty at completion, when
                                            // one is knowable and pushing is configured
                                            // on. See `push_at_completion_if_configured`'s
                                            // own doc for the honest-absence rules.
                                            push_at_completion_if_configured(
                                                context,
                                                &envelope,
                                                capsule_json,
                                                checkpoints.as_ref(),
                                                &self_peer,
                                            )
                                            .await;
                                        }
                                        lifecycle_events.record(envelope);
                                    }
                                    Err(join_error) => {
                                        // Best-effort observability: a
                                        // panicked/cancelled seal task is
                                        // logged, never propagated (the
                                        // envelope was consumed by the task,
                                        // so there is nothing left to record).
                                        tracing::warn!(%join_error, "observed-exchange seal task did not complete");
                                    }
                                }
                            } else {
                                lifecycle_events.record(envelope);
                            }
                        }
                        Err(error) => {
                            tracing::warn!(%error, "unparseable openai.exchange.v1 envelope");
                        }
                    }
                }
                Ok(())
            })
        })
    })
    .customize(move |plugin| {
        // the record-push responder
        // seals a LOCAL citing record onto THIS node's own chain after the
        // door confirms a received half -- so it needs the SAME single-writer
        // `CapsuleState` every other local seal uses. Cloned into the handler
        // closure (an `Arc`, so this is a refcount bump, one ledger).
        let capsules_for_stream = capsules_for_stream.clone();
        plugin.on_open_stream(move |request, context| {
            let capsules = capsules_for_stream.clone();
            Box::pin(async move {
                // Seam A1: `OpenStreamRequest`
                // carries no channel name (see `record_push_bridge`'s module
                // doc), so the single `on_open_stream` slot dispatches on
                // `content_type`, the one field both carriers set to a
                // distinct, stable value for exactly this purpose.
                if request.content_type.as_deref() == Some(record_push_bridge::RECORD_PUSH_CONTENT_TYPE) {
                    record_push_bridge::handle_open_stream(request, context, capsules).await
                } else {
                    mesh_evidence_bridge::handle_open_stream(request, context).await
                }
            })
        })
    })
    .customize(move |plugin| {
        plugin.on_mesh_event(move |event, _context| {
            let self_peer = self_peer_for_events.clone();
            Box::pin(async move {
                if self_peer.learn(&event.local_peer_id) {
                    tracing::info!(peer_id = %event.local_peer_id, "own mesh peer id reported by the host");
                }
                Ok(())
            })
        })
    })
    .customize(|plugin| plugin.with_operation_router(evidence_operations))
    .build();

    PluginRuntime::run(plugin).await
}

#[cfg(test)]
mod push_eligibility_tests {
    use super::*;
    use lifecycle_channel::{DispatchPath, HostServingProvenance, Phase};

    fn remote_mesh_envelope(served_by_node_id: Option<&str>) -> OpenAiExchangeEnvelope {
        OpenAiExchangeEnvelope {
            exchange_id: None,
            dispatch_path: DispatchPath::RemoteMesh,
            phase: Phase::Terminal,
            model: "some-model".to_string(),
            status: Some(200),
            capsule_id: None,
            capsule_id_provenance: None,
            nonce: None,
            serving_provenance: served_by_node_id.map(|id| HostServingProvenance {
                served_by_node_id: Some(id.to_string()),
                hostname: None,
                quantization: None,
                architecture: None,
                context_length: None,
                parameter_size: None,
                layer_count: None,
                model_identity_hash: None,
                weights_digest: None,
                model_canonical_ref: None,
                model_revision: None,
                gpu: None,
                vram_bytes: None,
                is_soc: None,
                requested_by_node_id: None,
            }),
            usage: None,
            request_digest: None,
            response_digest: None,
            tool_calls_digest: None,
            reasoning_digest: None,
            twin_bracket_id: None,
        }
    }

    fn host_served_envelope() -> OpenAiExchangeEnvelope {
        let mut envelope = remote_mesh_envelope(Some("irrelevant-self-id"));
        envelope.dispatch_path = DispatchPath::TypedFrontend;
        envelope
    }

    /// A real host-served terminal as the fork host publishes it for a request
    /// that arrived over the mesh tunnel: raw-proxy path, 2xx, this node's own
    /// loaded model (a `weights_digest`), and `requested_by_node_id` naming the
    /// node that asked.
    fn tunneled_host_served_envelope(requested_by: Option<&str>) -> OpenAiExchangeEnvelope {
        let mut envelope = remote_mesh_envelope(Some("self-m3"));
        envelope.dispatch_path = DispatchPath::RawProxy;
        let provenance = envelope
            .serving_provenance
            .as_mut()
            .expect("fixture has provenance");
        provenance.weights_digest = Some("sha256:loaded-weights".to_string());
        provenance.requested_by_node_id = requested_by.map(str::to_string);
        envelope
    }

    // MUTANT: delete `push_eligibility`'s `if record_at_completion_off {
    // return None; }` early return and this goes red -- the required
    // "policy off -> no push" behavior.
    #[test]
    fn policy_off_never_pushes_even_with_a_known_counterparty_and_self_id() {
        let envelope = remote_mesh_envelope(Some("peer-m3"));
        assert_eq!(push_eligibility(&envelope, true, Some("self-m4")), None);
    }

    #[test]
    fn policy_on_pushes_when_counterparty_and_self_id_are_both_known() {
        let envelope = remote_mesh_envelope(Some("peer-m3"));
        assert_eq!(
            push_eligibility(&envelope, false, Some("self-m4")),
            Some(("peer-m3", "self-m4"))
        );
    }

    #[test]
    fn no_self_peer_id_configured_never_pushes() {
        let envelope = remote_mesh_envelope(Some("peer-m3"));
        assert_eq!(push_eligibility(&envelope, false, None), None);
    }

    // MUTANT: make `skipped_for_missing_self_id` return None unconditionally
    // (the old silent skip) and the first assertion goes red.
    #[test]
    fn a_push_skipped_only_for_a_missing_self_id_is_reported() {
        let envelope = remote_mesh_envelope(Some("peer-m3"));
        assert_eq!(
            skipped_for_missing_self_id(&envelope, false, None),
            Some("peer-m3")
        );
        // Not reported when the push goes ahead, when policy is off, or when
        // there is no counterparty to push to anyway.
        assert_eq!(
            skipped_for_missing_self_id(&envelope, false, Some("self-m4")),
            None
        );
        assert_eq!(skipped_for_missing_self_id(&envelope, true, None), None);
        let nobody = remote_mesh_envelope(None);
        assert_eq!(skipped_for_missing_self_id(&nobody, false, None), None);
    }

    // Option A: the provider pushes its
    // sealed half to the node that asked -- the other direction of the same
    // exchange. MUTANT: return `None` from `push_counterparty`'s host-served
    // arm and this goes red.
    #[test]
    fn host_served_terminal_pushes_to_the_node_that_asked() {
        let envelope = tunneled_host_served_envelope(Some("peer-m4"));
        assert_eq!(
            push_eligibility(&envelope, false, Some("self-m3")),
            Some(("peer-m4", "self-m3"))
        );
    }

    // Never to itself: the served-by id (this node) is not a counterparty.
    #[test]
    fn host_served_terminal_never_pushes_to_its_own_served_by_id() {
        let envelope = tunneled_host_served_envelope(Some("peer-m4"));
        assert_ne!(push_counterparty(&envelope), Some("self-m3"));
    }

    // A request on this node's local API has no requesting mesh node; the host
    // sends none, so nothing is pushed -- never fabricated.
    #[test]
    fn host_served_terminal_from_the_local_api_never_pushes() {
        let envelope = tunneled_host_served_envelope(None);
        assert_eq!(push_eligibility(&envelope, false, Some("self-m3")), None);
    }

    #[test]
    fn host_served_terminal_with_unknown_requester_never_pushes() {
        let envelope = tunneled_host_served_envelope(Some("unknown"));
        assert_eq!(push_eligibility(&envelope, false, Some("self-m3")), None);
    }

    // Policy off wins on the provider side too.
    #[test]
    fn host_served_terminal_with_policy_off_never_pushes() {
        let envelope = tunneled_host_served_envelope(Some("peer-m4"));
        assert_eq!(push_eligibility(&envelope, true, Some("self-m3")), None);
    }

    // Not a real served exchange (no loaded-model identity: the plugin's own
    // stub shape), so it is not a sealable host-served terminal -- a requester
    // id on it is never used.
    #[test]
    fn a_non_sealable_host_served_shape_never_pushes_even_with_a_requester() {
        let mut envelope = host_served_envelope();
        envelope
            .serving_provenance
            .as_mut()
            .unwrap()
            .requested_by_node_id = Some("peer-m4".to_string());
        assert_eq!(push_eligibility(&envelope, false, Some("self-m3")), None);
    }

    // The host's JSON field lands in the mirror (and is optional on the wire).
    #[test]
    fn requested_by_node_id_deserializes_from_the_host_envelope_and_defaults_absent() {
        let with: HostServingProvenance = serde_json::from_value(
            serde_json::json!({"served_by_node_id": "m3", "requested_by_node_id": "m4"}),
        )
        .expect("parse");
        assert_eq!(with.requested_by_node_id.as_deref(), Some("m4"));
        let without: HostServingProvenance =
            serde_json::from_value(serde_json::json!({"served_by_node_id": "m3"})).expect("parse");
        assert_eq!(without.requested_by_node_id, None);
    }

    #[test]
    fn remote_mesh_with_no_served_by_node_id_has_no_knowable_counterparty() {
        let envelope = remote_mesh_envelope(None);
        assert_eq!(push_eligibility(&envelope, false, Some("self-m4")), None);
    }

    #[test]
    fn remote_mesh_with_unknown_served_by_node_id_has_no_knowable_counterparty() {
        let envelope = remote_mesh_envelope(Some("unknown"));
        assert_eq!(push_eligibility(&envelope, false, Some("self-m4")), None);
    }
}
