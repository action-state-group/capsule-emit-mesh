# mesh-full-ladder-rehearsal — EVIDENCE

Run date: 2026-09-05. Runner: coder session `coder-mesh-full-ladder-rehearsal`, lane `neutral`.
Node reachability verified mechanically at run time (`curl`, `tailscale status`, `ping`) —
see RUNBOOK.md's topology table. **This is a partial pass**: only M4 was reachable. Nothing
below claims a cross-node result it didn't actually run.

## Pass/fail/gated/blocked table

| # | Step | Status | Command | Observed | Artifact |
|---|---|---|---|---|---|
| 1a | M4 seals its own join card | **PASS** | `run_local_pass.py::step1_join_card` | `card_digest=8ef5a365...` recomputed == stored; real M4 Max hardware block | `out/01_join_card_m4.json` |
| 1a-weights | join card carries `weights_digest` | **GATED — unstacked** | — | `weights_digest=None` (`[mesh-weights-digest-at-load]` not stacked on running binary) | `out/01_join_card_m4.json` |
| 1b | M3 seals its own join card | **BLOCKED — node unreachable** | — | tailscale: `swim-googles` offline, last seen ~53m | — |
| 1c | Mini seals its own join card | **BLOCKED — node unreachable** | — | `joes-mac-mini.local`: `Unknown host` | — |
| 2 | M4→M3 exchange, E15 pull, `received()` | **BLOCKED — node unreachable** | — | no counterparty | — |
| 2 | M4→Mini exchange, E15 pull, `received()` | **BLOCKED — node unreachable** | — | no counterparty | — |
| 2 | sequence numbers 1..n per pair | **BLOCKED — node unreachable** | `python3 -c "import sequence_counter"` | module imports cleanly; no counterparty pair has any recorded sequence | — |
| 3 | M4 checkpoint sealed | **PASS** (stub witness, not a real receipt — see caveat) | `witness.push()` under `CAPSULE_WITNESS=stub` | `mmr_size=31 root=6960dbe0...` | `out/02_checkpoint_local_stub_witness.json` |
| 3 | M3/Mini checkpoints | **BLOCKED — node unreachable** | — | — | — |
| 3 | peer-root exchange visible on gossip | **GATED — unstacked** | — | `PeerAnnouncement` gossip field (`38823775d`) not stacked | — |
| 4 | `chain_segment{last:1}` self-query | **PASS** | `evidence_request.answer(...)` | `Artifact`, `leaf_counts={"capsule":16}` | `out/03_chain_segment_last1.json` |
| 4 | `record` query for real digest | **PASS** | `evidence_request.answer(...)` | `Artifact` for `b06a0e81...` | `out/04_record_query.json` |
| 4 | `record` query for never-sealed digest → `no_such_record` | **PASS** | `evidence_request.answer(...)` | `Refusal(reason="no_such_record")`, `verify_refusal_offline()==True` | `out/05_no_such_record_refusal.json` |
| 4 | two askers, same request, byte-identical | **PASS** | pinned `now=`, compared `json.dumps(..., sort_keys=True)` | equal | `out/06_two_askers_asker_a.json`, `out/07_two_askers_asker_b.json` |
| 4 | stranger (Mini/M3) asks M3 | **BLOCKED — node unreachable** | — | — | — |
| 5 | twin via `x-mesh-target`, logprobs agree → `corroborated` | **GATED — unstacked** + **BLOCKED — node unreachable** | — | `x-mesh-target` (`452664019`) + twin `/v1` not stacked; also needs 2 live nodes | — |
| 6 | all 6 mutants | **BLOCKED — node unreachable** | — | each depends on a live 2-3-node exchange from phase 2/5 | — |
| 7 | `correlation{counterparty: M3}` | **BLOCKED — node unreachable**, also **not landed** | — | `SUBJECT_KINDS = {record, range, chain_segment}` on `origin/main@df50185` — no `correlation` kind yet; `[mesh-e14-correlation-subject]` still open | — |

## Totals

- **PASS:** 6 (join card self-seal, checkpoint seal, chain_segment self-query, record query,
  no_such_record refusal, byte-identical two-askers)
- **GATED — unstacked** (code exists, not in the running binary): 3 (weights_digest in join
  card, peer-root gossip field, x-mesh-target/twin routing)
- **BLOCKED — node unreachable:** everything requiring M3 or Mini — Phases 1b/1c, all of
  Phase 2, M3/Mini's own checkpoints in Phase 3, the cross-node stranger-ask in Phase 4, the
  node-reachability half of Phase 5, all of Phase 6, all of Phase 7.
- **Not yet landed** (independent of reachability): `correlation` subject kind (Phase 7).

## Why this is a partial pass, not a red one

Every BLOCKED line above is a live infrastructure fact, not a design or code failure:
`swim-googles` (M3) was offline in `tailscale status` for the full duration of this run
(~53-54 min stale at last check), and `joes-mac-mini.local` (Mini) never resolved from this
host's network. Re-run once both are back online — the RUNBOOK.md re-run section has the
exact commands. This partial pass does **not** clear the gate on
`[mesh-full-ladder-rehearsal]` (still 🔴 GATES THE UPSTREAM PR TRAIN per the inbox item) —
the final full 3-node pass with Steven watching is still required.

## Boundary note: raw artifacts are held out of the public repo

The `out/*.json` files this pass produced (bundles for the `record`/`chain_segment`
queries) embed the FULL real capsule receipt from the live M4 ledger, which includes
`hostname: "Stevens-MacBook-Pro.local"` — the operator's actual machine name. This repo
is `boundary: public`. Rather than redact-and-commit (which would reduce the evidentiary
value of "this is exactly what the responder returned"), this pass keeps the raw
`out/*.json` and `ledger-m4-snapshot/` (which also holds a fresh, rehearsal-only Ed25519
signing key auto-generated for the snapshot — NOT the real M4 node's production key)
**untracked in the worktree**, persisted to `/Users/intangible/dev/asg/_work/mesh-full-ladder-rehearsal/`
outside any repo, and **not pushed**. Only this EVIDENCE.md, RUNBOOK.md, and the
`run_local_pass.py` script that produced them (which contains no captured data, only
code) are committed to the branch. An operator can re-run the script locally to
regenerate the raw artifacts, or pull them from the persisted `_work/` copy.

## Environment notes for the next runner

- Live M4 ledger: `/tmp/m4-mesh-node/data/ledger/` (real, do not treat as disposable — this
  rehearsal only ever read from it, via a snapshot copy at `ledger-m4-snapshot/`, and never
  wrote to the live one).
- `/tmp/m4-mesh-node/data/ledger/capsules.jsonl.bak-tampered-line12-1788566642` — a leftover
  from an earlier, unrelated session's mutant test against the live ledger. Not produced by
  this pass; flagged in RUNBOOK.md Phase 6 so it isn't mistaken for this rehearsal's own
  output.
- `capsule-emit` and `capsule-emit-mesh` canonical checkouts were fast-forwarded to
  `origin/main` during this pass (both were clean, both were behind — see RUNBOOK.md's code
  state section for exact SHAs). No fork branches were touched; no rebase was performed on
  anything upstream, per the manager's instruction.
