//! Byte-for-byte cross-check of this crate's JCS/capsule_id implementation
//! against the Python reference's frozen `vectors/capsule/canonical-*`
//! fixtures (`agent-action-capsule/vectors/capsule/`, spec §2/§5.1's
//! JSON-DIGEST -- plain RFC 8785 JCS, SHA-256, lowercase hex; no absent-field
//! normalization under format 4, the draft-04 reversal -- see `jcs`'s module
//! docs). Each `canonical-*` fixture is a full format-4 capsule object (its
//! own `capsule_id` field included) whose `expected.json.capsule_id_recomputed`
//! is `compute_capsule_id(input.json)` -- i.e. plain JCS over the object with
//! `capsule_id` (and the producer-envelope-only `signature`/`key_id`) removed.
//! Re-pinned 2026-09-25 [mesh-seal-path-draft-04-golden-vectors]: the prior
//! `test-vectors/` directory (arbitrary-JSON inputs, an `exception` field for
//! FloatInDigestError/UnsafeIntegerError, a `"canonical"` `kind` value) no
//! longer exists upstream -- replaced by `vectors/capsule/`, where the
//! canonicalization-only cases are the `canonical-`-prefixed names (all
//! `kind: "positive"`, no `exception` field; float/unsafe-int rejection is
//! now exercised by full-capsule `neg-*` vectors outside this crate's scope).
//!
//! `#[ignore]`d and gated on `AAC_TEST_VECTORS_DIR` (same shape as
//! `admission-policy`'s `tests/host_runtime_e2e.rs`): this crate's CI has no
//! checkout of the private multi-repo workspace the vectors live in (see
//! `.github/workflows/ci.yml`). Run it for real with:
//!   AAC_TEST_VECTORS_DIR=/path/to/agent-action-capsule/vectors/capsule \
//!     cargo test --test jcs_vectors -- --ignored

use capsule_producer::jcs::compute_capsule_id;
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
        .filter(|c| c["name"].as_str().is_some_and(|n| n.starts_with("canonical-")))
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert!(
        !canonical_cases.is_empty(),
        "expected at least one canonical-prefixed vector"
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

        let expected_digest = expected["capsule_id_recomputed"]
            .as_str()
            .unwrap_or_else(|| panic!("{name}: expected.json has no capsule_id_recomputed"));

        match compute_capsule_id(&input) {
            Ok(digest) => assert_eq!(
                digest, expected_digest,
                "{name}: capsule_id mismatch (Rust vs Python reference)"
            ),
            Err(e) => panic!(
                "{name}: Rust rejected input the Python reference digested \
                 (expected {expected_digest}): {e}"
            ),
        }
        checked += 1;
    }
    eprintln!("{checked} canonical vectors matched byte-for-byte");
}
