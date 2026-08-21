//! Real-host end-to-end test: drives the compiled `admission-policy-plugin`
//! binary through an ACTUAL running `mesh-llm-host-runtime` process (the
//! `mesh-llm serve` binary), not the faithful-but-fake-host stand-in in
//! `tests/interop.rs`. This closes the gap `tests/interop.rs` documents at
//! its top: it proves the plugin's `inference::provider()` registration is
//! dispatched real OpenAI-compatible HTTP traffic by mesh-llm's own routing
//! (`mesh-llm-host-runtime::network::openai::ingress::route_missing_local_model`
//! / `try_route_plugin_model`), not just by a test harness that reimplements
//! the host side of the wire protocol.
//!
//! Ignored by default and gated on `MESH_LLM_HOST_BIN` because
//! `mesh-llm-host-runtime` is not published to crates.io and pulls in
//! mesh-llm's native GPU/runtime toolchain (iroh, skippy-runtime, etc.) —
//! exactly the reason `tests/interop.rs` gives for not depending on it
//! directly. This repo's CI cannot build that workspace, so this test cannot
//! run there. It is a real, reproducible LOCAL verification path: see
//! `REAL-HOST-VERIFICATION.md` for the exact commands used to build a real
//! `mesh-llm` binary and the verified transcript.
//!
//! Run with:
//!   MESH_LLM_HOST_BIN=/path/to/mesh-llm/target/debug/mesh-llm \
//!     cargo test --test host_runtime_e2e -- --ignored --test-threads=1
//!
//! Run against the deliberately-broken mutant (proves this test actually
//! discriminates correct behavior from the exact regression the admission
//! policy exists to catch — same shape as `tests/interop.rs`'s mutant proof,
//! but exercised through the real host this time):
//!   MESH_LLM_HOST_BIN=/path/to/mesh-llm/target/debug/mesh-llm \
//!     cargo test --test host_runtime_e2e --features mutant-allow-blocked \
//!     -- --ignored --test-threads=1
//! (expected: `denies_blocked_model_end_to_end_through_real_host` FAILS)

use std::io::Write;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::{Child, Command};
use tokio::time::{sleep, timeout};

const PLUGIN_BIN: &str = env!("CARGO_BIN_EXE_admission-policy-plugin");
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

struct RealHost {
    child: Child,
    api_port: u16,
    home_dir: PathBuf,
}

impl RealHost {
    async fn spawn() -> Self {
        let host_bin = std::env::var("MESH_LLM_HOST_BIN").expect(
            "MESH_LLM_HOST_BIN must point to a real `mesh-llm` binary \
             (built from mesh-llm's own workspace: `cargo build -p mesh-llm --bin mesh-llm`). \
             See REAL-HOST-VERIFICATION.md.",
        );
        assert!(
            std::path::Path::new(&host_bin).is_file(),
            "MESH_LLM_HOST_BIN '{host_bin}' does not exist"
        );

        // Deliberately NOT `std::env::temp_dir()`: on macOS that resolves to
        // a long per-process `/var/folders/.../T/` path, and the real host
        // derives its plugin Unix-domain-socket path from `$HOME`
        // (`{HOME}/.mesh-llm/run/plugins/p<pid>-<nonce>-<plugin>.sock`) —
        // long enough to exceed `sockaddr_un`'s ~104-byte `sun_path` limit
        // and fail the plugin's bind with no further detail. `/tmp` directly
        // keeps the whole path well under that limit.
        let home_dir = PathBuf::from("/tmp").join(format!("ape2e-{}", nonce()));
        std::fs::create_dir_all(&home_dir).expect("create isolated HOME for real host");

        let api_port = pick_port();
        let console_port = pick_port();

        let config_path = home_dir.join("config.toml");
        let mut config_file = std::fs::File::create(&config_path).expect("create config.toml");
        writeln!(
            config_file,
            r#"version = 1

[[plugin]]
name = "admission-policy"
enabled = true
command = "{PLUGIN_BIN}"
args = []
"#
        )
        .expect("write config.toml");

        let log_path = home_dir.join("run.log");
        let log_file = std::fs::File::create(&log_path).expect("create run.log");

        let child = Command::new(&host_bin)
            .args([
                "serve",
                "--config",
                config_path.to_str().unwrap(),
                "--port",
                &api_port.to_string(),
                "--console",
                &console_port.to_string(),
                "--headless",
                "--disable-iroh-relays",
                "--log-format",
                "json",
            ])
            .env("HOME", &home_dir)
            .env(
                "ADMISSION_POLICY_BLOCKED_MODELS",
                "blocked-test-model,allowed-test-model",
            )
            .stdin(Stdio::null())
            .stdout(Stdio::from(log_file.try_clone().expect("clone log fd")))
            .stderr(Stdio::from(log_file))
            .kill_on_drop(true)
            .spawn()
            .expect("spawn real mesh-llm host");

        let host = Self {
            child,
            api_port,
            home_dir,
        };
        host.wait_for_plugin_model("allowed-test-model").await;
        host
    }

    /// Poll the host's own `/v1/models` until the plugin's health-probe
    /// cycle (`mesh-llm-host-runtime::plugin::health`) has picked up the
    /// declared model — proves the real Initialize handshake, the real HTTP
    /// health probe, and the real routing table are all live, not just that
    /// the process started.
    async fn wait_for_plugin_model(&self, model: &str) {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let url = format!("http://127.0.0.1:{}/v1/models", self.api_port);
        let deadline = tokio::time::Instant::now() + STARTUP_TIMEOUT;
        loop {
            if tokio::time::Instant::now() > deadline {
                let log = std::fs::read_to_string(self.home_dir.join("run.log"))
                    .unwrap_or_else(|e| format!("<could not read run.log: {e}>"));
                panic!(
                    "real host never advertised '{model}' via /v1/models within {STARTUP_TIMEOUT:?}. \
                     Host log:\n{log}"
                );
            }
            if let Ok(resp) = client.get(&url).send().await {
                if let Ok(body) = resp.text().await {
                    if body.contains(model) {
                        return;
                    }
                }
            }
            sleep(Duration::from_millis(500)).await;
        }
    }

    async fn post_chat_completions(&self, body: &serde_json::Value) -> reqwest::Response {
        let client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .unwrap();
        timeout(
            REQUEST_TIMEOUT,
            client
                .post(format!(
                    "http://127.0.0.1:{}/v1/chat/completions",
                    self.api_port
                ))
                .json(body)
                .send(),
        )
        .await
        .expect("request to real host did not time out")
        .expect("POST /v1/chat/completions to real host")
    }

    async fn post_chat_completions_raw(&self, body: &str) -> reqwest::Response {
        let client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .unwrap();
        timeout(
            REQUEST_TIMEOUT,
            client
                .post(format!(
                    "http://127.0.0.1:{}/v1/chat/completions",
                    self.api_port
                ))
                .header("content-type", "application/json")
                .body(body.to_string())
                .send(),
        )
        .await
        .expect("request to real host did not time out")
        .expect("POST /v1/chat/completions to real host")
    }
}

impl Drop for RealHost {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
        let _ = std::fs::remove_dir_all(&self.home_dir);
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

fn pick_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .map(|l| l.local_addr().unwrap().port())
        .expect("bind ephemeral port")
}

/// (A) Deny, dispatched by the real host's real routing table — not a direct
/// call to the plugin's own HTTP port. Proves `inference::provider()`
/// registration + exact-name model dispatch
/// (`mesh-llm-host-runtime::network::openai::ingress::try_route_plugin_model`)
/// works against the actual host, matching `tests/interop.rs`'s test (C) but
/// through the real process instead of the fake-host stand-in.
///
/// This is also the mutant-discriminating check: built with
/// `--features mutant-allow-blocked`, the real host still dispatches the
/// request to the (broken) plugin, which now answers 200 instead of 403 —
/// this assertion fails, proving the check actually exercises the plugin's
/// decision logic end-to-end rather than passing regardless of it.
#[tokio::test]
#[ignore = "requires a real mesh-llm host binary; see MESH_LLM_HOST_BIN and REAL-HOST-VERIFICATION.md"]
async fn denies_blocked_model_end_to_end_through_real_host() {
    let host = RealHost::spawn().await;
    let resp = host
        .post_chat_completions(&serde_json::json!({
            "model": "blocked-test-model",
            "messages": []
        }))
        .await;
    assert_eq!(resp.status(), reqwest::StatusCode::FORBIDDEN);
    let body: serde_json::Value = resp.json().await.expect("valid JSON body");
    assert_eq!(body["error"]["code"], "blocked_model_prefix");
}

/// (B) Allow, dispatched by the real host. `allowed-test-model` is advertised
/// by the plugin (so the host's exact-name routing sends it there) but does
/// not match the blocked prefix, so the plugin's own decision logic allows
/// it. Demonstrates the full allow/deny matrix end-to-end, not just deny.
#[tokio::test]
#[ignore = "requires a real mesh-llm host binary; see MESH_LLM_HOST_BIN and REAL-HOST-VERIFICATION.md"]
async fn allows_unblocked_advertised_model_end_to_end_through_real_host() {
    let host = RealHost::spawn().await;
    let resp = host
        .post_chat_completions(&serde_json::json!({
            "model": "allowed-test-model",
            "messages": []
        }))
        .await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("valid JSON body");
    assert_eq!(body["admission_policy"]["decision"], "allow");
}

/// (C) Malformed input through the real host's standard ingress — with an
/// important, verified architectural difference from `tests/interop.rs`'s
/// (D): on the real host, a syntactically-unparseable body never reaches the
/// plugin at all. `network::openai::ingress::api_proxy` parses the "model"
/// field from the request body BEFORE any routing decision (including the
/// plugin fallback) can be made; when that parse fails outright, the host
/// itself returns a non-200 error (observed: 503, "single target None
/// unavailable") without ever opening a connection to the plugin's HTTP
/// endpoint. So the plugin's own `body_parse_failure` fail-safe branch
/// (`decision::malformed`, and the `mutant-allow-malformed` feature that
/// breaks it) is real and correctly wired — proven directly in
/// `tests/interop.rs` and `src/decision.rs`'s unit tests, which talk to the
/// plugin's HTTP endpoint directly — but is NOT reachable through this real
/// host's `/v1/chat/completions` ingress in this single-plugin topology, so
/// it cannot be re-verified at this layer. What IS verified here: the real
/// host's OWN behavior on unparseable input is fail-safe (never a silent
/// 200), independent of the plugin.
///
/// (A second, more surprising case — valid JSON with a missing/non-string
/// "model" field — is NOT malformed from the real host's point of view: its
/// model-resolution fallback rewrites such requests to name the sole
/// available target ("blocked-test-model" in this topology) before
/// forwarding, so the plugin correctly denies them for the
/// `blocked_model_prefix` reason, not `body_parse_failure`. Verified
/// manually; see REAL-HOST-VERIFICATION.md. Only a body that fails to parse
/// as JSON at all defeats the host's routing outright.)
#[tokio::test]
#[ignore = "requires a real mesh-llm host binary; see MESH_LLM_HOST_BIN and REAL-HOST-VERIFICATION.md"]
async fn malformed_body_fails_safe_at_the_real_host_before_reaching_the_plugin() {
    let host = RealHost::spawn().await;
    let resp = host.post_chat_completions_raw("{not valid json").await;
    assert_ne!(
        resp.status(),
        reqwest::StatusCode::OK,
        "unparseable body must never be silently allowed, at the host or the plugin"
    );
}
