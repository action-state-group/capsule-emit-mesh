//! The evidencebook crate's `reconcile_halves` reaches the same outcome as
//! the Python correlator (`served_request_join.join_served_request`) and the
//! Go evidence book's `ReconcileHalves` on real halves sealed by this repo's
//! Python sidecar.
//!
//! `tests/fixtures/reconcile_parity.json` is the Go implementation's
//! `testdata/reconcile-parity/fixture.json`, copied byte for byte: each pair
//! is a requester half and a provider half plus the Python correlator's
//! outcome on them, and the Go test replays the same pairs. The crate knows
//! no key names; this plugin supplies them as a join policy, reading them
//! from where its capsules carry them: `exchange_id` and `twin_bracket_id`
//! from `serving_provenance`, the request digest from
//! `compute_attestation.agent_input_digest`.
//!
//! A half counts as trusted here when its `capsule_id` recomputes from its
//! body. The Go test uses the full AAC verifier for that; this test checks
//! correlation, not verification.

use capsule_producer::jcs::compute_capsule_id;
use evidencebook::reconcile::{reconcile_halves, Half, HalfSet, JoinPolicy, PairState, Tallies};
use serde_json::Value;
use std::collections::BTreeMap;

const EXCHANGE_ID: &str = "exchange_id";
const REQUEST_DIGEST: &str = "request_digest";
const TWIN_BRACKET_ID: &str = "twin_bracket_id";

fn policy() -> JoinPolicy {
    JoinPolicy {
        primary: EXCHANGE_ID.into(),
        secondary: REQUEST_DIGEST.into(),
        group: Some(TWIN_BRACKET_ID.into()),
    }
}

fn half(capsule: &Value) -> Half {
    let ca = &capsule["model_attestation"]["compute_attestation"];
    let sp = &ca["x-mesh-poc-v1"]["serving_provenance"];
    let mut correlation = BTreeMap::new();
    for (name, value) in [
        (EXCHANGE_ID, &sp["exchange_id"]),
        (REQUEST_DIGEST, &ca["agent_input_digest"]),
        (TWIN_BRACKET_ID, &sp["twin_bracket_id"]),
    ] {
        if let Some(v) = value.as_str() {
            correlation.insert(name.to_string(), v.to_string());
        }
    }
    let record_id = capsule["capsule_id"].as_str().unwrap().to_string();
    Half {
        trusted: compute_capsule_id(capsule).unwrap() == record_id,
        record_id,
        seq: 0,
        correlation,
        payload_commitments: vec![],
        covered: true,
    }
}

#[test]
fn reconcile_matches_the_python_correlator_and_go_on_every_pair() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/reconcile_parity.json")).unwrap();
    let pairs = fixture["pairs"].as_array().unwrap();
    assert!(pairs.len() >= 6, "fixture lost its pairs");
    let agree = |_: &Half, _: &Half| true;
    let (mut want, mut got) = (Tallies::default(), Tallies::default());

    for pair in pairs {
        let name = pair["name"].as_str().unwrap();
        let (a, b) = (half(&pair["requester"]), half(&pair["provider"]));
        assert!(
            a.trusted && b.trusted,
            "{name}: a sealed half does not recompute"
        );
        let (results, t) = reconcile_halves(
            &HalfSet {
                halves: vec![a],
                complete: true,
            },
            &HalfSet {
                halves: vec![b],
                complete: true,
            },
            &policy(),
            &agree,
        );
        got.matched += t.matched;
        got.a_only += t.a_only;
        got.b_only += t.b_only;
        got.conflicting += t.conflicting;

        let python = &pair["python"];
        match python["outcome"].as_str().unwrap() {
            "joined" => {
                want.matched += 1;
                assert_eq!(results.len(), 1, "{name}: {results:?}");
                assert_eq!(results[0].state, PairState::Matched, "{name}");
                assert_eq!(
                    results[0].join_key.as_deref(),
                    python["join_key"].as_str(),
                    "{name}"
                );
                let twin = python["twin_bracket_id"].as_str().filter(|s| !s.is_empty());
                assert_eq!(results[0].group.as_deref(), twin, "{name}");
            }
            "conflicting" => {
                want.conflicting += 1;
                assert_eq!(results.len(), 1, "{name}: {results:?}");
                assert_eq!(results[0].state, PairState::Conflicting, "{name}");
                assert_eq!(results[0].join_key.as_deref(), Some(EXCHANGE_ID), "{name}");
            }
            "no_correlation" => {
                want.a_only += 1;
                want.b_only += 1;
                let states: Vec<PairState> = results.iter().map(|r| r.state).collect();
                assert_eq!(states, [PairState::AOnly, PairState::BOnly], "{name}");
            }
            other => panic!("{name}: unknown python outcome {other:?}"),
        }
    }
    assert_eq!(got, want);
}
