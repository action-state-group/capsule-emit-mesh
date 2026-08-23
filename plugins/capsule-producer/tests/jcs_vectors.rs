//! Byte-for-byte cross-check of this crate's JCS implementation against the
//! Python reference's frozen `test-vectors/canonical-*` fixtures
//! (`agent-action-capsule/test-vectors/`, spec §2/§5.1's JSON-DIGEST — RFC 8785
//! JCS canonicalization of an absent-field-normalized value, SHA-256, lowercase
//! hex). Each fixture's `expected.json.capsule_id_recomputed` is exactly
//! `json_digest(input.json)` — no capsule-shape validation involved, so it
//! exercises the canonicalizer directly, independent of the AAC model.
//!
//! `#[ignore]`d and gated on `AAC_TEST_VECTORS_DIR` (same shape as
//! `admission-policy`'s `tests/host_runtime_e2e.rs`): this crate's CI has no
//! checkout of the private multi-repo workspace the vectors live in, so the
//! test only compile-checks there (see `.github/workflows/ci.yml`). Run it for
//! real with:
//!   AAC_TEST_VECTORS_DIR=/path/to/agent-action-capsule/test-vectors \
//!     cargo test --test jcs_vectors -- --ignored

use capsule_producer::jcs::{json_digest, JcsError};
use serde_json::Value;
use std::path::PathBuf;

#[test]
#[ignore]
fn canonical_vectors_match_python_byte_for_byte() {
    let dir = match std::env::var("AAC_TEST_VECTORS_DIR") {
        Ok(d) => PathBuf::from(d),
        Err(_) => {
            eprintln!("AAC_TEST_VECTORS_DIR not set; skipping (see module docs)");
            return;
        }
    };

    let manifest: Value = serde_json::from_slice(
        &std::fs::read(dir.join("vectors.json")).expect("read vectors.json"),
    )
    .expect("parse vectors.json");
    let cases = manifest["cases"].as_array().expect("cases array");
    let canonical_cases: Vec<&str> = cases
        .iter()
        .filter(|c| c["kind"] == "canonical")
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert!(
        !canonical_cases.is_empty(),
        "expected at least one canonical-kind vector"
    );

    let mut checked = 0;
    for name in &canonical_cases {
        let case_dir = dir.join(name);
        let input: Value = serde_json::from_slice(
            &std::fs::read(case_dir.join("input.json"))
                .unwrap_or_else(|e| panic!("read {}/input.json: {e}", case_dir.display())),
        )
        .unwrap_or_else(|e| panic!("parse {}/input.json: {e}", case_dir.display()));
        let expected: Value = serde_json::from_slice(
            &std::fs::read(case_dir.join("expected.json")).expect("read expected.json"),
        )
        .expect("parse expected.json");

        let actual = json_digest(&input);
        match expected.get("exception").and_then(Value::as_str) {
            // Python's reference rejects this input (FloatInDigestError /
            // UnsafeIntegerError) — Rust must reject it too, with the matching
            // error variant, not silently digest it.
            Some("FloatInDigestError") => assert!(
                matches!(actual, Err(JcsError::FloatInDigest)),
                "{name}: expected FloatInDigestError, got {actual:?}"
            ),
            Some("UnsafeIntegerError") => assert!(
                matches!(actual, Err(JcsError::UnsafeInteger(_))),
                "{name}: expected UnsafeIntegerError, got {actual:?}"
            ),
            Some(other) => panic!("{name}: unhandled expected exception {other:?}"),
            None => {
                let expected_digest =
                    expected["capsule_id_recomputed"]
                        .as_str()
                        .unwrap_or_else(|| {
                            panic!("{name}: expected.json has no capsule_id_recomputed")
                        });
                match actual {
                    Ok(digest) => assert_eq!(
                        digest, expected_digest,
                        "{name}: JCS digest mismatch (Rust vs Python reference)"
                    ),
                    Err(e) => panic!(
                        "{name}: Rust JCS rejected input that Python's reference digested \
                         (expected {expected_digest}): {e}"
                    ),
                }
            }
        }
        checked += 1;
    }
    eprintln!("{checked} canonical vectors matched byte-for-byte");
}
