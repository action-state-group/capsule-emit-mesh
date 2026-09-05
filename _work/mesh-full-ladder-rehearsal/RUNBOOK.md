# mesh-full-ladder-rehearsal — RUNBOOK

Repo: `capsule-emit-mesh` (+ `capsule-emit` for the evidence-request/chain_segment/witness
primitives). Node topology as briefed by the manager at rehearsal time
(2026-09-05, ~07:15 PT):

| Node | Address | Role in ladder | Reachability at rehearsal time |
|---|---|---|---|
| M4  | `localhost:9338` (mesh-llm `ActionCapsuleMeshM4`, real Apple M4 Max) | this host | **live** — verified `{"status":"ok"}`, real `mesh-llm` process (pid 28590), real ledger at `/tmp/m4-mesh-node/data/ledger` |
| M3  | `100.127.121.98` (tailscale `swim-googles`) | requester/provider peer | **offline** — tailscale: "active; relay sfo; offline, last seen 52-54m ago" at every check during this pass |
| Mini | `joes-mac-mini.local` | third node / stranger / referee | **unresolvable** — no mDNS answer from this host (`Stevens-MacBook-Pro.local`, LAN `192.168.7.0/24`); not present in this tailnet under any name |

The GCP node named in the original inbox item does not exist in the current mesh; per
the manager's 2026-09-05 update, Mini (`joes-mac-mini.local`) stands in for it in the
ladder below, wherever both are reachable.

**Code state at rehearsal time** (canonical checkouts fast-forwarded to `origin/main`,
read-only — no rebase, no push, no edits to fork branches):
- `capsule-emit` → `origin/main` @ `df50185` (0.7.1 release; includes `chain_segment`
  subject, #151, merged 2026-09-05T04:44:15Z).
- `capsule-emit-mesh` → `origin/main` @ `ce4725f` (includes `join_card.py`,
  `sequence_counter.py`, `adjudication_delivery.py`, margin-gated `twin_adjudicator.py`,
  and `peer_root_ledger.rs` — the RECEIVING half of peer-root reconciliation).
- Fork demo branch `feat/serving-provenance-host-served-terminal` (mesh-llm,
  `StevenMih/mesh-llm`) — has PR #7 (routing-node terminal events, `d849c89ea`) stacked.
  `weights_digest` (`03a12affb`), `x-mesh-target` (`452664019`), twin `/v1` routing, and
  the peer-root **gossip field** (`38823775d`) are on their own fork branches, **not yet
  stacked** onto the demo branch — Steven's stacking call is pending. Anything that needs
  one of these is marked `GATED — unstacked` below, not red.

Every step below: **command → expected → observed → artifact path**. A step is one of:
- **PASS** — ran for real against live M4 state or a snapshot of it; artifact attached.
- **GATED — unstacked** — the code exists on a fork branch but isn't in the running
  binary/plugin yet; not this rehearsal's fault, not a red mark.
- **BLOCKED — node unreachable** — needs a second/third node; M3 and Mini were both
  unreachable for the entire duration of this pass (see table above).

---

## Phase 1 — three nodes join, each seals a join card

**M4 (live, single-node — no peer required):** a join card is a standalone self-report
(`join_card.py`: `build_card()` + `seal_card()`), not a peer-handshake artifact — it can
be sealed at any time, alone.

```
PYTHONPATH="<capsule-emit>:<capsule-emit-mesh>" python3 run_local_pass.py   # step1_join_card()
```
- **Expected:** a sealed capsule whose `compute_attestation["x-mesh-join-card-v1"]` block
  contains `card_digest == Card.digest()` recomputed from the same fields (self-consistency,
  no trust-the-signer-blindly check).
- **Observed:** `card_digest = 8ef5a36553762b815175057eabb0e7d1442354a19344517ecb0c322c9d10a60c`,
  hardware_inventory = real `system_profiler`-sourced M4 Max block (Mac16,5, 14 CPU cores,
  32 GPU cores, 38654705664 bytes RAM), 1 served model
  (`local-gguf/sha256-1993f98e085eaa51`), `weights_digest = None`.
  **PASS**, with one caveat: `weights_digest` is `None` because `[mesh-weights-digest-at-load]`
  (the fork branch that stamps a weights digest at model-load time) is not stacked on the
  running mesh-llm binary. **GATED — unstacked** for the weights-digest field specifically;
  the card mechanism itself is PASS.
- **Artifact:** `out/01_join_card_m4.json`

**M3 join card:** **BLOCKED — node unreachable.** Cannot start the M3 mesh-llm process or
its sidecar/plugin from here; nothing to seal.

**Mini join card:** **BLOCKED — node unreachable.** `joes-mac-mini.local` does not
resolve; same as above.

---

## Phase 2 — M4↔M3 and M4↔Mini exchanges, E15 pull, `received()`, sequence 1..n

All of Phase 2 requires a live counterparty. **BLOCKED — node unreachable** end to end:
- M4→M3 exchange, M4→Mini exchange: no peer to exchange with.
- E15 door pull (`evidence_server.py` `POST /evidence-request` + `ask_history.py`
  client, wrapping the same `capsule_emit.evidence_request.answer()` this rehearsal
  exercised directly in Phase 4 below): the RESPONDER side of this mechanism is proven
  live in Phase 4 (record query, `no_such_record` refusal, byte-identical askers) against
  M4's own ledger; what's blocked is a second node PULLING through it and calling
  `received()`.
- Sequence numbers 1..n per pair (`sequence_counter.py`, landed on `capsule-emit-mesh`
  main): the counter is keyed by `(self, counterparty)` — with no counterparty exchange
  recorded, M4's own ledger has nothing to count yet. Confirmed empty:
  `python3 -c "import sequence_counter"` imports cleanly (module present, PASS-the-import),
  but there is no live counterparty pair to report sequence state for.
  **BLOCKED — node unreachable** for a real 1..n sequence.

---

## Phase 3 — checkpoints on all three, witnessed; peer root exchange on gossip

**M4 (live, single-node slice):**
```
CAPSULE_WITNESS=stub python3 -c "from capsule_emit import witness; witness.push('<ledger>')"
```
- **Expected:** a `CheckpointRecord` covering every capsule sealed since the last
  checkpoint, MMR root + signature over it.
- **Observed:** `mmr_size=31`, `root=6960dbe0c00fea6f...`, one `WitnessRecord` with
  `ts_url="stub://local"`, `is_stub=True` — explicitly labeled by the library itself as
  "not a real COSE Receipt ... this checkpoint was never sent to a Transparency Service".
  **PASS for the checkpoint mechanics; NOT a real witness** — this rehearsal deliberately
  used the zero-network stub (`CAPSULE_WITNESS=stub`) rather than pushing a rehearsal
  checkpoint to the live production anchor (`anchor.agentactioncapsule.org`), since that
  is shared production infrastructure and out of scope for a local smoke pass. A real
  witnessed checkpoint is deferred to the full multi-node pass, run against the anchor
  deliberately rather than as a side effect of a rehearsal script.
- **Artifact:** `out/02_checkpoint_local_stub_witness.json`

**M3 / Mini checkpoints, and peer-root exchange visible on gossip:** **BLOCKED — node
unreachable** for M3/Mini's own checkpoints. Peer-root exchange is additionally
**GATED — unstacked**: the RECEIVING half of reconciliation
(`plugins/admission-policy/src/peer_root_ledger.rs`) is on `capsule-emit-mesh` main, but
the gossip field that CARRIES a peer's checkpoint root (`PeerAnnouncement`, fork commit
`38823775d`) is not yet stacked on the demo branch mesh-llm is running from — so even if
M3/Mini were reachable, no peer root would currently arrive over gossip to reconcile.

---

## Phase 4 — stranger asks `chain_segment`, `record`, unknown digest, byte-identical

**M4 (live, single-node — a stranger asking M4 about M4's own ledger is exactly this
node's `evidence_request.answer()` responder; the multi-node piece is WHO is asking, not
what the responder does):**

```python
from capsule_emit import evidence_request
evidence_request.answer(b'{"subject":{"kind":"chain_segment","last":1}}', ledger=ledger_path)
evidence_request.answer(b'{"subject":{"kind":"record","capsule_id":"<real digest>"}}', ledger=ledger_path)
evidence_request.answer(b'{"subject":{"kind":"record","capsule_id":"' + '0'*64 + '"}}', ledger=ledger_path)
```

- **`chain_segment{last:1}` — expected:** one `CheckpointLink` with `leaf_counts` by kind,
  `consistency_proof` (null for the first checkpoint), the checkpoint's own signature +
  witness receipts, COSE-wrapped checkpoint bytes.
  **Observed:** `leaf_counts: {"capsule": 16}`, `prev_size: 0`, `consistency_proof: null`
  (correct — first checkpoint has nothing prior to prove consistency against),
  witnesses = the stub witness from Phase 3. **PASS.**
  Artifact: `out/03_chain_segment_last1.json`
- **`record` for one real digest — expected:** an `Artifact` wrapping one `Bundle`.
  **Observed:** `Artifact` returned for
  `b06a0e8127da7413425778a60cef54b34360ba89ecabc397e4cee26d094b5114`. **PASS.**
  Artifact: `out/04_record_query.json`
- **Never-sealed digest → signed `no_such_record` — expected:** a `Refusal` with
  `reason == "no_such_record"` that verifies OFFLINE via
  `evidence_request.verify_refusal_offline()`.
  **Observed:** `Refusal(reason="no_such_record")`, `verify_refusal_offline() == True`.
  **PASS.** Artifact: `out/05_no_such_record_refusal.json`
- **Two askers → byte-identical — expected:** the same request, from two different
  askers, at the same instant, produces byte-identical wire output (the responder does
  not special-case who's asking).
  **Observed:** pinned `now=` to the same instant for both calls; `json.dumps(..., sort_keys=True)`
  output compared equal. **PASS.** Artifacts: `out/06_two_askers_asker_a.json`,
  `out/07_two_askers_asker_b.json`.
- **Stranger = GCP/Mini asking M3:** **BLOCKED — node unreachable** — this phase's
  responder mechanics are proven above against M4 acting as its own responder; a real
  cross-node stranger ask (Mini asking M3, or M3 asking M4) needs both ends reachable.

---

## Phase 5 — twin via `x-mesh-target` to M3 and Mini, logprobs agree → `corroborated`

**GATED — unstacked** (needs `x-mesh-target` routing, fork commit `452664019`, and twin
`/v1` routing, neither stacked) **and BLOCKED — node unreachable** (needs two live
serving nodes to compare). Both conditions independently block this phase; neither
alone would be enough to run it even if the other were satisfied.

The adjudicator MECHANISM itself is landed (`twin_adjudicator.py`, `adjudicate()`,
`compare_transcripts()`, margin-gated logprobs comparison — PRs #102/#103) and unit-tested
in-repo (`tests/test_twin_adjudicator.py`), but exercising it meaningfully needs either
(a) two real servings from two different nodes (blocked, no second node), or (b) the
same-owner-twin refusal path (`no_verdict_reason="same_owner_twin"`), which needs
disclosure preimages this rehearsal's host-served M4 captures don't carry. Deferred to
the multi-node pass rather than faked with a same-node substitute.

---

## Phase 6 — mutants

All six mutants in this phase are defined relative to a live 2-3-node exchange
(diverge a served answer, forge a delivery, drop a ledger entry, tamper a `prev_root`,
change hardware without a new card, referee a contradiction) — every one of them
needs at least the M4↔M3 or M4↔Mini pair from Phase 2, which is **BLOCKED — node
unreachable**.

Noted for the record: the live M4 ledger directory already contains
`ledger-m4-snapshot`-adjacent evidence that a `prev_root`-tamper mutant was rehearsed
against this same M4 ledger by an earlier, unrelated session — a file named
`capsules.jsonl.bak-tampered-line12-1788566642` sits next to the live
`capsules.jsonl` at `/tmp/m4-mesh-node/data/ledger/`. That backup was **not** produced
by this rehearsal and is excluded from this pass's own evidence; it is flagged here
only so the final full pass's author knows it exists and can decide whether to fold it
in or re-run it cleanly.

---

## Phase 7 — stranger asks M3's counterparties `correlation{counterparty: M3}`

**BLOCKED — node unreachable**, and also **not yet landed**: `capsule_emit.evidence_request
.SUBJECT_KINDS` on the current `origin/main` (`df50185`) is `{"record", "range",
"chain_segment"}` — there is no `correlation` subject kind yet. Per the inbox,
`[mesh-e14-correlation-subject]` is still open, blocked on `[mesh-requester-half-live-path]`
addendum (a) — so this phase is doubly blocked independent of node reachability.

---

## Re-running this pass

```
cd capsule-emit-mesh && git fetch origin && git log --oneline -1 origin/main   # confirm code state hasn't moved
cd _work/mesh-full-ladder-rehearsal && python3 run_local_pass.py
```
Re-run once M3/Mini are back online (check `tailscale status` for `swim-googles`, and
`ping joes-mac-mini.local` for Mini) and the fork-branch stacking call lands, to pick up
the phases marked BLOCKED/GATED above.
