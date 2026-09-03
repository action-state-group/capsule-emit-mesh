# TDX quote fixtures

Two genuine Intel TDX v4 DCAP quotes captured from a GCP C3 confidential VM
(non-paravisor TDX, `configfs-TSM` `tdx_guest` provider) on 2026-07-21.
Vendored byte-for-byte, unmodified, from:

- Source: `agentrust-io/agent-manifest@e1cd860`
- Path: `python/tests/fixtures/hardware/gcp-tdx-2026-07-21/`
- License: Apache-2.0 (source repo `LICENSE`)

| File | SHA-256 |
|---|---|
| `tdx_quote.bin` | `f9efbac112efe510aa8ccd20703b063591b8c2c54c474d0ff1d6500299bae0ba` |
| `tdx_quote_manifest.bin` | `1ae04c74b564ef8795d4c4e4ffd1835d080d9dad4f8879e5cd1e8249503828b2` |

Both quotes come from **one TD** and share the same MRTD:

```
9bf86e6280ec4282b8b5822d8166410a456cdb720109aa799f0011fa63df1de3ee5e35e293fc410c061433163acb03a6
```

They differ only in `REPORT_DATA` (the guest-controlled binding field). This
is deliberate: `tests/test_trace_citation.py`'s substitution mutant relies on
two independently-valid quotes that agree on measurement and disagree on
binding, to prove our grading never mistakes "same MRTD" for "same execution".

Verify with the dependency this repo actually uses (never a re-implementation):

```python
from agent_manifest._tdx_verify import verify_tdx_quote
verify_tdx_quote(open("tdx_quote.bin", "rb").read())  # -> True
```
