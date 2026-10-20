# T8 served summary fixture

`tests/test_served_summary_parity.py` checks that this repository's
`served_summary.py` answers `served_summary/1` with the same bytes as the
Mesh-LLM capsules plugin (`crates/evidence-plugin/src/served_summary.rs`),
and that an adjudication appended after the newest checkpoint does not change
them (PRD R-15, test T8; capsule-emit-mesh#229).

| File | Contents |
|---|---|
| `capsules.jsonl` | The plugin's parity corpus ledger (`vectors/parity/evidence_request/corpus.json`), plus one line: a copy of corpus line 8 (an adjudication of an own record) under a new capsule id, after the newest checkpoint |
| `checkpoints.jsonl` | The corpus's checkpoints, unchanged |
| `served_summary.json` | The plugin's `served_summary` for `served_summary/1` pinned to the newest checkpoint, compact with sorted keys |

**How it was made.** A scratch clone of Mesh-LLM/capsules at `efcada7`
gained one ignored test in `evidence_request_parity.rs` (never committed
anywhere). It ran the module's `run` over the corpus with the extra line and
wrote the answer's `served_summary`, which was the same for the cases
`served_summary` and `served_summary_to_a_counterparty` (two requesters).

At `efcada7` the plugin still counts adjudications over the whole log and
words the `adjudications_received` note differently, so the clone also
carried those two changes; until they land upstream, the plugin at that
commit does not produce this file. Regenerate it when the plugin's served
summary changes upstream.
