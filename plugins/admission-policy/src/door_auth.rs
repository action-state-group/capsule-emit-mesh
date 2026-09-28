//! evidence-door-auth v1: the plugin and its local evidence door
//! (`evidence_server.py`) prove to each other that they share this install's
//! token, so no other local process can pose as either.
//!
//! - The token is `<data dir>/evidence-door.token`: 64 lowercase hex chars,
//!   no newline, mode 0600, created by the plugin at startup if absent and
//!   never overwritten. The door reads it with `--token-file`. The HMAC key is
//!   the 64 ASCII chars as bytes.
//! - Every request carries `X-Evidence-Door-Nonce` (32 hex, fresh) and
//!   `X-Evidence-Door-Auth = hex(HMAC(key, "plugin\n" METHOD "\n" PATH "\n" NONCE))`.
//! - Every reply to it must carry
//!   `X-Evidence-Door-Proof = hex(HMAC(key, "door\n" NONCE "\n" STATUS "\n" hex(sha256(body))))`.
//!   A reply without a valid proof is never used or forwarded.
//!
//! A door that is not running, or cannot prove it holds the token, is
//! reported loudly (log + [`status`] for the page), never failed silently.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{bail, Context};
use rand_core::{OsRng, RngCore};
use serde::Serialize;
use sha2::{Digest, Sha256};

pub const TOKEN_FILE: &str = "evidence-door.token";
pub const NONCE_HEADER: &str = "X-Evidence-Door-Nonce";
pub const AUTH_HEADER: &str = "X-Evidence-Door-Auth";
pub const PROOF_HEADER: &str = "X-Evidence-Door-Proof";
pub const ENV_DOOR_URL: &str = "ADMISSION_POLICY_EVIDENCE_SERVER_URL";
const DEFAULT_DOOR_URL: &str = "http://127.0.0.1:8091";

static KEY: OnceLock<String> = OnceLock::new();

/// This node's evidence door (`evidence_server.py --listen-port`, default 8091).
pub fn door_url() -> String {
    std::env::var(ENV_DOOR_URL)
        .ok()
        .map(|u| u.trim().trim_end_matches('/').to_string())
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| DEFAULT_DOOR_URL.to_string())
}

fn is_token(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The install's token under `data_dir`, created if absent (never replaced).
pub fn ensure_token(data_dir: &Path) -> anyhow::Result<String> {
    let path = data_dir.join(TOKEN_FILE);
    std::fs::create_dir_all(data_dir).with_context(|| format!("create {}", data_dir.display()))?;
    let mut raw = [0u8; 32];
    OsRng.fill_bytes(&mut raw);
    let fresh = hex::encode(raw);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    match options.open(&path) {
        Ok(mut file) => {
            file.write_all(fresh.as_bytes())?;
            file.sync_all()?;
            Ok(fresh)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let text = std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
            if !is_token(&text) {
                bail!("{} is not a door token (64 lowercase hex, no newline)", path.display());
            }
            Ok(text)
        }
        Err(e) => Err(e).with_context(|| format!("create {}", path.display())),
    }
}

/// Load (or create) the token once at startup.
pub fn init(data_dir: &Path) -> anyhow::Result<PathBuf> {
    let token = ensure_token(data_dir)?;
    let _ = KEY.set(token);
    Ok(data_dir.join(TOKEN_FILE))
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut block = [0u8; BLOCK];
    if key.len() > BLOCK {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(block.map(|b| b ^ 0x36));
    inner.update(message);
    let mut outer = Sha256::new();
    outer.update(block.map(|b| b ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

pub fn request_auth(key: &str, method: &str, path: &str, nonce: &str) -> String {
    hex::encode(hmac_sha256(key.as_bytes(), format!("plugin\n{method}\n{path}\n{nonce}").as_bytes()))
}

pub fn reply_proof(key: &str, nonce: &str, status: u16, body: &[u8]) -> String {
    let body_digest = hex::encode(Sha256::digest(body));
    hex::encode(hmac_sha256(key.as_bytes(), format!("door\n{nonce}\n{status}\n{body_digest}").as_bytes()))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn fresh_nonce() -> String {
    let mut raw = [0u8; 16];
    OsRng.fill_bytes(&mut raw);
    hex::encode(raw)
}

/// Why a door call gave nothing usable.
#[derive(Debug)]
pub enum DoorError {
    /// Nothing listens at the door's address.
    NotRunning { url: String },
    /// The door refused our auth, or its reply carried no valid proof.
    AuthFailed { url: String },
    /// No token was loaded (startup did not run [`init`]).
    NoToken,
    Transport(anyhow::Error),
}

impl std::fmt::Display for DoorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DoorError::NotRunning { url } => write!(
                f,
                "evidence door isn't running at {url}; received peer records and record requests are not being handled"
            ),
            DoorError::AuthFailed { url } => {
                write!(f, "evidence door at {url} did not prove it holds the token; ignoring it")
            }
            DoorError::NoToken => write!(f, "no evidence door token loaded"),
            DoorError::Transport(e) => write!(f, "evidence door call failed: {e}"),
        }
    }
}

impl std::error::Error for DoorError {}

/// A door reply whose proof verified.
pub struct DoorReply {
    pub status: u16,
    pub body: Vec<u8>,
}

/// One authenticated call to the door at `path`. A reply is returned only
/// when its proof verifies; every failure is logged with the door's address.
pub async fn call(
    client: &reqwest::Client,
    method: reqwest::Method,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<Vec<u8>>,
) -> Result<DoorReply, DoorError> {
    let result = call_with_key(client, KEY.get().map(String::as_str), &door_url(), method, path, headers, body).await;
    if let Err(error) = &result {
        tracing::warn!(%error, "evidence door");
    }
    result
}

async fn call_with_key(
    client: &reqwest::Client,
    key: Option<&str>,
    base: &str,
    method: reqwest::Method,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<Vec<u8>>,
) -> Result<DoorReply, DoorError> {
    let key = key.ok_or(DoorError::NoToken)?;
    let nonce = fresh_nonce();
    let mut request = client
        .request(method.clone(), format!("{base}{path}"))
        .header(NONCE_HEADER, &nonce)
        .header(AUTH_HEADER, request_auth(key, method.as_str(), path, &nonce));
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    if let Some(body) = body {
        request = request.body(body);
    }
    let response = request.send().await.map_err(|e| {
        if e.is_connect() {
            DoorError::NotRunning { url: base.to_string() }
        } else {
            DoorError::Transport(e.into())
        }
    })?;
    let status = response.status().as_u16();
    let proof = response
        .headers()
        .get(PROOF_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = response.bytes().await.map_err(|e| DoorError::Transport(e.into()))?.to_vec();
    let expected = reply_proof(key, &nonce, status, &body);
    match proof {
        Some(proof) if constant_time_eq(proof.trim().as_bytes(), expected.as_bytes()) => Ok(DoorReply { status, body }),
        _ => Err(DoorError::AuthFailed { url: base.to_string() }),
    }
}

/// What the page shows about the door.
#[derive(Serialize, Debug, PartialEq)]
pub struct DoorStatus {
    /// `ready`, `not_running`, `auth_failed` or `unknown`.
    pub state: &'static str,
    pub url: String,
}

/// Probe the door (`GET /health`, authenticated).
pub async fn status() -> DoorStatus {
    let url = door_url();
    let client = match reqwest::Client::builder().timeout(Duration::from_secs(2)).build() {
        Ok(client) => client,
        Err(_) => return DoorStatus { state: "unknown", url },
    };
    let state = match call_with_key(&client, KEY.get().map(String::as_str), &url, reqwest::Method::GET, "/health", &[], None).await {
        Ok(reply) if reply.status == 200 => "ready",
        Ok(_) | Err(DoorError::Transport(_)) | Err(DoorError::NoToken) => "unknown",
        Err(DoorError::NotRunning { .. }) => "not_running",
        Err(DoorError::AuthFailed { .. }) => "auth_failed",
    };
    DoorStatus { state, url }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY0: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    const NONCE1: &str = "11111111111111111111111111111111";

    /// The vectors the door's own tests pin (evidence-door-auth v1).
    #[test]
    fn matches_the_doors_test_vectors() {
        assert_eq!(
            request_auth(KEY0, "POST", "/evidence/record-push", NONCE1),
            "44ffac9a4f0c74d4418a5a918d8e30624f8394ef80608c3773d328abed75ae6b"
        );
        assert_eq!(
            reply_proof(KEY0, NONCE1, 200, b"{}"),
            "9aec425e9b7ab34ffeeaadee5c646e7553ce3a6ff99dec51abab0f2e2d404f39"
        );
    }

    #[test]
    fn hmac_matches_rfc4231_case_2() {
        assert_eq!(
            hex::encode(hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    fn tmp(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("door-auth-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn the_token_is_created_once_with_owner_only_access_and_never_replaced() {
        let dir = tmp("token");
        let first = ensure_token(&dir).unwrap();
        assert!(is_token(&first));
        assert_eq!(std::fs::read_to_string(dir.join(TOKEN_FILE)).unwrap(), first, "no newline");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join(TOKEN_FILE)).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        assert_eq!(ensure_token(&dir).unwrap(), first);
    }

    #[test]
    fn a_malformed_token_file_is_refused_not_rewritten() {
        let dir = tmp("bad-token");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(TOKEN_FILE), format!("{KEY0}\n")).unwrap();
        assert!(ensure_token(&dir).is_err());
        assert_eq!(std::fs::read_to_string(dir.join(TOKEN_FILE)).unwrap(), format!("{KEY0}\n"));
    }

    /// A one-shot local door: answers one request with `status`/`body`, and
    /// a proof made with `proof_key` (None: no proof header).
    async fn fake_door(status: u16, body: &'static [u8], proof_key: Option<&'static str>) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let n = socket.read(&mut buf).await.unwrap();
            let head = String::from_utf8_lossy(&buf[..n]).to_string();
            let nonce = head
                .lines()
                .find_map(|l| l.to_ascii_lowercase().strip_prefix("x-evidence-door-nonce:").map(|v| v.trim().to_string()))
                .unwrap_or_default();
            let proof = proof_key
                .map(|k| format!("{PROOF_HEADER}: {}\r\n", reply_proof(k, &nonce, status, body)))
                .unwrap_or_default();
            let reply = format!(
                "HTTP/1.1 {status} X\r\nContent-Length: {}\r\n{proof}Connection: close\r\n\r\n",
                body.len()
            );
            socket.write_all(reply.as_bytes()).await.unwrap();
            socket.write_all(body).await.unwrap();
        });
        format!("http://127.0.0.1:{port}")
    }

    #[tokio::test]
    async fn a_reply_is_used_only_when_its_proof_verifies() {
        let client = reqwest::Client::new();
        let base = fake_door(200, b"{\"ok\":true}", Some(KEY0)).await;
        let reply = call_with_key(&client, Some(KEY0), &base, reqwest::Method::POST, "/evidence/record-push", &[], Some(b"{}".to_vec()))
            .await
            .unwrap();
        assert_eq!(reply.body, b"{\"ok\":true}");

        let base = fake_door(200, b"{\"ok\":true}", None).await;
        let err = call_with_key(&client, Some(KEY0), &base, reqwest::Method::POST, "/x", &[], None).await;
        assert!(matches!(err, Err(DoorError::AuthFailed { .. })), "no proof");

        let base = fake_door(200, b"{\"ok\":true}", Some("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")).await;
        let err = call_with_key(&client, Some(KEY0), &base, reqwest::Method::POST, "/x", &[], None).await;
        assert!(matches!(err, Err(DoorError::AuthFailed { .. })), "proof under another key");

        let base = fake_door(401, b"{\"error\":\"door_auth_failed\"}", None).await;
        let err = call_with_key(&client, Some(KEY0), &base, reqwest::Method::GET, "/health", &[], None).await;
        assert!(matches!(err, Err(DoorError::AuthFailed { .. })), "the door refused our auth");
    }

    #[tokio::test]
    async fn a_door_that_is_not_listening_is_reported_as_not_running() {
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let base = format!("http://127.0.0.1:{port}");
        let err = call_with_key(&reqwest::Client::new(), Some(KEY0), &base, reqwest::Method::GET, "/health", &[], None).await;
        match err {
            Err(e @ DoorError::NotRunning { .. }) => assert!(e.to_string().contains("isn't running at http://127.0.0.1:")),
            other => panic!("expected NotRunning, got {:?}", other.err()),
        }
    }
}
