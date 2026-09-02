> **About the entries in `ledger-redteam-live/`**
>
> This directory is the committed HONEST-run artifact from
> [`DEMO-REDTEAM.md`](../DEMO-REDTEAM.md) / `scripts/redteam_live_demo.sh` —
> one real capsule, sealed by `capsule_sidecar.py` in front of the live M4
> `mesh-llm` node, for one real served inference. `scripts/redteam_live_demo.sh`
> (with or without `--tamper`) deletes and regenerates this directory on every
> run; what's committed here is the state left by a clean (non-`--tamper`) run
> so the fixture always shows GREEN, not whatever the last local rehearsal
> happened to leave behind.
>
> Same demo-grade caveats as [`ledger-live/README.md`](../ledger-live/README.md):
> self-attested node key, no owner/hardware binding. This entry's own
> `hardware`/`hostname` fields read `null` (not fabricated) — see
> `DEMO-REDTEAM.md`'s honesty box for why.
