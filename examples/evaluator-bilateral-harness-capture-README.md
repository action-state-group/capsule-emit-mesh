# Evaluator-bilateral harness capture — three runs, reconciled

`evaluator_bilateral_harness_capture_demo.py` runs the same requester-side
capture against three counterparty situations and reconciles each with
`capsule_emit.reconciliation` (see that module's own docs in the
`capsule-emit` repo, `docs/bilateral-reconciliation.md`, for the full
three-state semantics — this page covers the mesh-specific mechanics only).

```bash
pip install -e .   # or: pip install -r requirements.txt
python examples/evaluator_bilateral_harness_capture_demo.py [--out-dir DIR]
```

Defaults to writing bundles to `~/dev/asg/_work/evaluator-bilateral/`.
Everything runs on `127.0.0.1` at ports far from both the protected M4 demo
node (`:3131`/`:9337`) and `bilateral_demo.py`'s own ports; nothing here
ever calls `--publish` — every server is loopback-only, private by
construction.

## The three runs

- **`run_a_mesh_provider.json`** — a requester-role `capsule_sidecar.py`
  chained through a provider-role `capsule_sidecar.py` in front of the
  fixture model node. Both sidecars independently seal a capsule for the
  same exchange (correlated by `serving_provenance.exchange_id`, the
  response-id lineage both derive from the same wire bytes). Reconciles
  `matched`.
- **`run_b_plain_api.json`** — the requester-role sidecar points straight at
  the fixture model node, which runs no capsule producer at all. There is
  no counterparty half to find. Reconciles `requester_only` — the "not
  present" state, never rendered as an error.
- **`run_c_spoofed.json`** — the METR vector. A second, independent record
  of run A's exchange is sealed as a downstream reviewer's transcript would
  show it, with the response content altered after the fact (`SPOOFTEST` in
  place of what actually executed). Reconciled against run A's own
  harness-sealed capsule — the record of what the sidecar actually observed
  on the wire — it reconciles `contradicted`.

Each bundle carries the raw capsules, the per-exchange reconciliation
result, and the fold counts (`N of M`, never a percentage).

## Which mesh path this exercises — read before citing these bundles

This repo documents two ways a provider seals its half (`README.md`, "Path
1" / "Path 2"). **This demo runs Path 2** (`capsule_sidecar.py`, an external
reverse-proxy observer) **against `mock_mesh_node.py`**, the repo's own
documented fixture stand-in for a real Mesh-LLM node (see that module's own
docstring — this sandbox cannot execute a downloaded mesh-llm binary
either, same reason `bilateral_demo.py` uses the same fixture).

**Path 1** — the native Rust `admission-policy` + `capsule-producer` plugin
pair, riding a real `mesh-llm-host-runtime` process actually serving a
model — was not exercised in this session. Bringing it up for real needs a
downloaded GGUF model and a built host runtime carrying the fork's
lifecycle hooks: materially heavier than a `cargo build`, and this
workspace's own serialize-cargo-builds safety rule exists because that
class of build has taken the host machine down before. This is a scoping
decision for this task, not a claim that Path 2 is a lesser mechanism —
both paths write the identical capsule shape
(`compute_attestation.agent_input_digest`/`agent_output_digest`,
`serving_provenance.exchange_id`), and this repo's own README says neither
vantage is "strictly superior" — but it IS a different claim about which
producer actually sealed this run's provider half, and anyone citing these
bundles should carry that distinction forward rather than round it up to
"the mesh plugin."

## What this establishes, and what it does not

Same discipline as `capsule_emit.adapters.inspect_ai` and
`capsule_emit.reconciliation`:

- `matched` establishes that two independently-sealed records of the same
  exchange agree — not that the exchange happened in some stronger sense,
  and not that the two signers are distinct parties (that is a policy input
  a verifier supplies, not a property these capsules carry — see
  `docs/bilateral-reconciliation.md`'s Sybil paragraph, and
  `capsule_sidecar.py`'s own `derive_cross_party_rung`/
  `identity_limitation_for_rung` for the same caveat on the separate
  Move-1..4 bilateral-attestation axis, which this demo does not exercise).
- `contradicted` establishes that the two records disagree — it does not by
  itself say which one is true; in run C the harness's own sealed record is
  the source of truth *by construction of this demo*, not because
  reconciliation can tell true from false on its own.
- Neither state says anything about an agent (or an operator) that
  compromises the sealing process itself, or about any call that was never
  routed through either sidecar in the first place.

## Cost

Each run is a handful of loopback HTTP calls and local capsule sealing —
no network egress, no anchor call (these run with the default local
ledger only). The reconciliation fold itself is pure local computation over
records both sides already sealed (see `docs/bilateral-reconciliation.md`'s
own cost line in the `capsule-emit` repo).
