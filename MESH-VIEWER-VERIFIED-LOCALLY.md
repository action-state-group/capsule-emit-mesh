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

## Update — requester-only + inference-forward (user feedback)

Feedback: *"I'd like it to just be the requester only. It's hard to understand
what was sent and what came back — I can't see the inference returned even after
I opened the evidence."* Two changes plus one bug fix.

### A. Requester-only by default (`--role requester|provider|coordinator|third_party|all`)
The **requester's** 3 questions render inline by default; the other three roles
fold behind a collapsed **"other roles"** toggle — carried in the payload, never
deleted. `--role all` restores the original 4-roles-×-3-questions inline layout.
`payload.default_role` drives the browser; `DEFAULT_ROLE == "requester"`.

### B. Inference-forward conversation block, disclosed + digest-verified
Each capsule now **leads** with a words-first
`Prompt (sent)` → `Response (came back)` block naming
*served by `<node>`, `<model> <quant>` on `<gpu>`*. Disclosed text is verified
against exactly the digest the capsule sealed, honestly:

- **Response** — the served **model + token usage** (`{model, usage}`) is
  recomputed **in-browser** (the same canonical JSON-DIGEST the Rust seal path
  binds) and compared to `response_digest` → a green **"✓ matches sealed
  digest"** chip. The response **text** is the requester's held copy: on the
  host-served observe path the plugin never sees the streamed body (documented
  in `emit_for_observed_host_exchange` and the demo's `b-tool_calls.json`), so
  the block states plainly that `response_digest` binds the served facts, not
  the text — no false "the text matches a text-digest" claim.
- **Request** — when the requester supplies the exact request **body** it is
  digest-verified against `request_digest`; when only the human-readable prompt
  is held (as in this demo), the chip honestly reads **"request body not held in
  this bundle — request_digest sealed"** (`matches: None`), never a faked match.

The 3 requester accountability questions and the per-field sealed-vs-shown
disclosure control stay **below** the conversation (secondary).

### C. Bug fix — self-contained embed serialization
The self-contained embed jammed the base64 into the JS boot **guard**
(`if (embedded && embedded !== ""<base64>…`) instead of only the
`window.__MESH_FRAGMENT_B64U__="…"` placeholder — a JS syntax error that blanked
the page (see `_work/mesh-live-demo/mesh-live-demo-permalink.html.bak`). Fixed so
the fragment lands in **exactly one** place (the placeholder), the guard sentinel
is assembled at runtime (`"@@"+"FRAGMENT"+"@@"`) so a substitution can never
overwrite it, and `render_mesh_viewer_html` asserts exactly one placeholder and
that the fragment never leaks into the guard.

### D. Tests
```
$ pytest tests/test_capsule_mesh_viewer.py tests/test_mesh_viewer_js_parity.py \
         tests/test_mesh_viewer_boot_render.py -q
30 passed
$ pytest tests/ -q
506 passed, 6 skipped
```
- `test_capsule_mesh_viewer.py` (+13): requester default; all roles still
  carried; served-facts digest == the seal construction; conversation leads with
  a **verified** inference; mismatch shown honestly; prompt stays sealed when the
  body isn't held; request-body verifies when the exact bytes are held;
  tool-calls note carried; **embed lands only in the placeholder / boot guard
  intact / renderer asserts one placeholder** (the corruption regression).
- `test_mesh_viewer_js_parity.py` (+1, node): the browser `servedFactsDigest`
  recomputes byte-for-byte the same digest as the Python seal construction.
- `test_mesh_viewer_boot_render.py` (new, node): the **delivered self-contained
  HTML** boots with no JS syntax error and renders the conversation with a green
  served-facts chip (skips cleanly without node).

### E. Real render — requester-only, inference-forward
`_work/mesh-live-demo/mesh-demo-REQUESTER.html` — the 3 M3 `swim-googles`
host-served capsules, requester-only, all 3 conversations **disclosed** and
digest-verified:
- (a) *how great is mesh-llm* → the model's "I don't have information about
  mesh-llm…" answer;
- (b) *mesh-llm vs SETI@Home research* → the real `web_search` **tool_call**
  (`web_search({"query":"mesh-llm vs SETI@Home"})`), with the tool-call note
  referencing `b-tool_calls.json`;
- (c) *give me your passwords / why trust you* → the refusal.

Headless render check (payload decodes, `boot()` parses with no syntax error,
3 conversations render, each served-facts digest matches its sealed
`response_digest`): **PASS**. Response texts (a) and (c) are byte-identical to
the requester-held `requester-responses/*-response.json` `content`.

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
