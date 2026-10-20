# Evidence answer interop with the Mesh-LLM capsules plugin

`plugin/` holds evidence request replies built by the Mesh-LLM capsules
plugin (`crates/evidence-plugin/src/evidence_artifact.rs`,
`evidence_answer::answer_and_log`) at Mesh-LLM/capsules commit `27043e6`,
the head of Mesh-LLM/capsules#32, over the plugin's own parity corpus
(`evidence_request_parity::corpus_ledger_dir`, node key `NODE_KEY_SEED`). Each
file is `{request_hex, reply, responder}`: the request octets as sent, the
reply as the plugin sends it, and the responder's Ed25519 key (hex). Every
reply passed the plugin's own requester (`evidence_artifact::check`) when it
was built.

| File | Request |
|---|---|
| `record-first-anchor.json` | `record` (corpus line 3), pinned to the first anchor: no consistency proof |
| `record-consistency.json` | `record` (corpus line 17), pinned to the second anchor: with its consistency proof |
| `range.json` | `range` `[16, 18]`, pinned to the second anchor |
| `range-min-freshness.json` | `range` `[0, 2]` under `min_freshness: 1` |
| `checkpoints.json` | `checkpoints` under `min_freshness: 0` |

`tests/test_evidence_interop_plugin.py` reads each with `ask_history`.

`served-summary-t8/` holds the plugin's `served_summary/1` answer over its
corpus with a line appended after the newest checkpoint; its own README says
how it was made, and `tests/test_served_summary_parity.py` checks it.

**How they were made, and the other direction.** A scratch clone of
Mesh-LLM/capsules at `27043e6` gained one test in `evidence_artifact.rs`'s
test module (never committed anywhere). It wrote these replies with the
module's `node().ask(...)` helper, and it ran the plugin's `check` over
answers this repository's door (`evidence_responder.answer_wire`) gave for
`record` (with and without a consistency proof), `range`, `full_history`,
`correlation`, `checkpoints` and `served_summary/1`, with real witness
receipts from the hermetic stub Transparency Service of
`tests/test_ask_the_references.py`. Every Mesh answer checked out
(capsule-emit-mesh#224). Regenerate both after the plugin's forms change
upstream.
