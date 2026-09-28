//! A test stand-in for the evidence door's side of evidence-door-auth v1:
//! a known token seeded into the plugin's data dir before it starts (the
//! plugin keeps an existing token), and the reply proof the door adds.

use sha2::{Digest, Sha256};

pub const TEST_DOOR_TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// Create `data_dir` holding [`TEST_DOOR_TOKEN`] as its door token.
pub fn seed_token(data_dir: &std::path::Path) {
    std::fs::create_dir_all(data_dir).expect("create the plugin data dir");
    std::fs::write(data_dir.join("evidence-door.token"), TEST_DOOR_TOKEN).expect("seed the door token");
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut block = [0u8; 64];
    block[..key.len()].copy_from_slice(key);
    let mut inner = Sha256::new();
    inner.update(block.map(|b| b ^ 0x36));
    inner.update(message);
    let mut outer = Sha256::new();
    outer.update(block.map(|b| b ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

/// The nonce header's value in a raw request head.
pub fn request_nonce(request: &[u8]) -> String {
    String::from_utf8_lossy(request)
        .lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("x-evidence-door-nonce:")
                .map(|v| v.trim().to_string())
        })
        .unwrap_or_default()
}

/// The `X-Evidence-Door-Proof` header line for a reply.
pub fn proof_header(nonce: &str, status: u16, body: &[u8]) -> String {
    let body_digest = hex::encode(Sha256::digest(body));
    let proof = hmac_sha256(TEST_DOOR_TOKEN.as_bytes(), format!("door\n{nonce}\n{status}\n{body_digest}").as_bytes());
    format!("X-Evidence-Door-Proof: {}\r\n", hex::encode(proof))
}
