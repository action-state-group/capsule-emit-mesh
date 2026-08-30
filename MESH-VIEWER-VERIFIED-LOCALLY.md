<!-- SPDX-License-Identifier: Apache-2.0 -->
# Mesh capsule viewer — Verified locally

`capsule_mesh_viewer.py` + `mesh_viewer_static/mesh_verify.js` render mesh
capsules as a **words-first, role-organised, offline, fragment-carried** HTML
viewer: the 4 roles × 3 questions of the mesh accountability build plan (§6),
each answered from the capsule's `serving_provenance` fields, digests hidden
behind an expander, disclosure per-field. It is a thin plug-in over the neutral
fragment-carried-permalink *mechanism* (the same one
`capsule_ledger.bundle_viewer` / `report.render` ship), composing
`capsule_mesh_view`'s existing role/counterparty labels — not a fork, and not a
new dependency on capsule-ledger.

## What was verified, and how

### 1. Python unit + shape tests (runs in CI's `Unit tests` step)
```
$ pytest tests/test_capsule_mesh_viewer.py -q
13 passed
```
Covers: nested + legacy-flat `serving_provenance` flattening; the words-first
model line carries no digest; every role has exactly 3 questions; the four
coordinator/witness states; disclosure closed-by-default (digest-only) and
opening only the named field; fragment round-trip carrying the full record;
`render_mesh_viewer_html` is self-contained (no `<script src>`, no `http`, no
`fetch`) yet reads `location.hash`.

### 2. Browser-side capsule_id recompute is byte-exact with the Python reference
`mesh_verify.js` recomputes each `capsule_id` in-browser (the "verifies
offline" claim). Its JCS/absent-field-normalize port is checked against
`agent_action_capsule.compute_capsule_id` under node:
```
$ pytest tests/test_mesh_viewer_js_parity.py -q
1 passed          # skips cleanly when node is absent (e.g. the clean-venv CI)
```
Driven over real mesh capsules of both shapes (ledger-live flat + a nested
capsule-producer/0.2.0 capsule): JS id == Python id == stored id, all match.

### 3. Full existing suite stays green (no regression)
```
$ pytest tests/ -q
490 passed, 6 skipped
```

### 4. Real-data render, offline
Rendered from real workspace data to `_work/mesh-viewer-demo/`:
- `mesh-viewer-real-capture.html` — 2 capsules from
  `mesh-real-model-capture/capsules.jsonl` (plugin log) **with** the COSE
  checkpoint receipt. Third-party "record complete / not equivocated" reads
  **answered (anchored)** because the witness checkpoint was supplied.
- `mesh-viewer-ledger-live.html` — 4 capsules from `ledger-live/capsules.jsonl`
  (Hermes-2-Pro-Mistral-7B Q4_K_M), **no** witness, with one adversarial refusal
  **disclosed** and the other content fields kept digest-only.

Both open with **zero external references** (verified: no `<script src>`, no
`http`, no `fetch`) and re-derive every `capsule_id` in the browser from the
fragment alone.

## Answerable-from-the-record today vs "not yet in the record"

| Role · question | Today |
|---|---|
| Requester Q1 (model/quant/hardware) | **answered** ← `serving_provenance` |
| Requester Q2 (prove to a stranger) | **partial** — signed record (+ witness if supplied); no counterparty countersign (Move 4) yet |
| Requester Q3 (good history with node) | **not in record** — edge predicate over own history, not one capsule |
| Provider Q1 (who asked, verified?) | **answered** iff `cross_party.initiator_ref` present, else **partial** (unknown = honest self-attested rung) |
| Provider Q2 (served honestly, not liable) | **answered** ← gate verdict + digests-only (non-retention) |
| Provider Q3 (keep serving them?) | **not in record** — edge predicate |
| **Coordinator Q1–Q3** (slice order / bounded knowledge / honest routing) | **not in record** — the coordinator stage-order receipt is **NOT YET BUILT** (build plan §3, B6) |
| Third-party Q1 (happened as claimed) | **answered** iff verify ok + model present, else **partial** |
| Third-party Q2 (complete / not equivocated) | **answered** iff a witness COSE checkpoint is supplied, else **not in record** in this view |
| Third-party Q3 (evaluate unwitnessed claim) | **partial** — offline-verifiable bundle + relying-party predicate; "nobody is the authority" |

The coordinator row is the honest gap: single-node exchanges carry no
split-inference topology, and the coordinator receipt type is spec-in-progress
(B6), so those three questions are labelled **not yet in the record** rather
than faked.
