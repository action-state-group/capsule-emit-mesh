#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Evaluator-bilateral harness capture — three runs, reconciled.

An evaluation harness (or any requester) seals its own half of every model
call it makes, the way ``capsule_emit.adapters.inspect_ai`` does at the
Inspect boundary. This demo runs the SAME requester-side sealing against
three different counterparty situations, and reconciles each with
``capsule_emit.reconciliation``:

  RUN A — mesh provider exists. Two ``capsule_sidecar.py`` sidecars, one per
  role (``--role requester`` in front of the harness's own client, ``--role
  provider`` in front of the serving node), chained: harness -> requester
  sidecar -> provider sidecar -> model. Both halves seal a capsule for the
  same exchange (correlated by ``serving_provenance.exchange_id`` — the
  response id lineage, see ``capsule_sidecar.exchange_id_from_response``);
  reconciliation reports ``matched``.

  RUN B — plain API endpoint, no provider half. The requester sidecar
  points directly at the fixture model node, which runs no capsule producer
  at all. Reconciliation reports the counterparty half ``requester_only`` —
  a first-class "not present" state, never "failed".

  RUN C — the METR spoofed-tool-call vector. A second, independent record of
  RUN A's exchange is sealed as a downstream reviewer's transcript would
  show it, with the response altered after the fact
  (``SPOOFTEST`` in place of the real content). Reconciled against the
  harness's own sealed record of RUN A, it reports ``contradicted``.

WHICH MESH PATH THIS EXERCISES — read before citing this as "the provider
half where it exists" without qualification
------------------------------------------------------------------------------
This repo documents two ways a provider seals its half (README.md "Path 1"
/ "Path 2"). Path 1 is the native Rust `admission-policy` + `capsule-
producer` plugin pair, riding a real `mesh-llm-host-runtime` process serving
an actual model. Path 2 is `capsule_sidecar.py`, an external reverse-proxy
observer that requires zero changes to the serving node and works against
either a real `mesh-llm serve` process or (as here) `mock_mesh_node.py`, the
repo's own documented fixture stand-in for one (see that module's
docstring: this sandbox cannot execute a downloaded mesh-llm binary either).

This demo runs Path 2, not Path 1. Bringing up Path 1 for real needs a real
GGUF model file and a built `mesh-llm-host-runtime` (the fork carrying
#1437's lifecycle hooks) — materially heavier than this session's scope, and
the workspace's own cargo-build safety rule (serialize through
`ci-one-at-a-time.sh`, one Rust build at a time, OOM risk) exists because
that exact build has crashed the host machine before. Path 2 is not a
weaker claim about the MECHANISM — both paths write the same capsule shape
(`compute_attestation.agent_input_digest` / `agent_output_digest`,
`serving_provenance.exchange_id`), and this repo's own README says neither
vantage is "strictly superior" — but it IS a different claim about WHICH
producer sealed this run's provider half, and that distinction belongs in
front of anyone citing these bundles.

Run:  python3 examples/evaluator_bilateral_harness_capture_demo.py [--out-dir DIR]
Exit code 0 iff all three runs reconcile to the state each is supposed to
reach.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from capsule_emit.reconciliation import (
    ReconciliationState,
    fold,
    format_fold,
    reconcile,
)

import mock_mesh_node
from capsule_sidecar import (
    ROLE_PROVIDER,
    ROLE_REQUESTER,
    ThreadingHTTPServer,
    default_state,
    run_sidecar,
)

MODEL_ID = mock_mesh_node.MODEL_ID

# Ports deliberately far from the protected M4 demo node (:3131/:9337) and
# from bilateral_demo.py's own ports (9341/8093), so this can run alongside
# either without colliding. Never --publish; every server here binds
# 127.0.0.1 only.
MOCK_PORT = 19341
PROVIDER_SIDECAR_PORT = 19342
REQUESTER_SIDECAR_PORT_CHAINED = 19343  # RUN A: requester -> provider -> mock
REQUESTER_SIDECAR_PORT_PLAIN = 19344  # RUN B: requester -> mock directly


def _wait_for(url: str, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            urllib.request.urlopen(url, timeout=0.5)
            return
        except Exception:
            time.sleep(0.05)
    raise TimeoutError(f"server at {url} did not come up in time")


def _post_chat(port: int, prompt: str) -> tuple[int, dict[str, Any]]:
    body = json.dumps(
        {
            "model": MODEL_ID,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.2,
            "max_tokens": 64,
            "seed": 42,
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        url=f"http://127.0.0.1:{port}/v1/chat/completions",
        data=body,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def _start_mock_node(port: int) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", port), mock_mesh_node.Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    _wait_for(f"http://127.0.0.1:{port}/v1/models")
    return server


def _start_sidecar(
    *, out_dir: Path, name: str, role: str, node_id: str, listen_port: int, upstream_port: int
) -> ThreadingHTTPServer:
    node_dir = out_dir / name
    state = default_state(
        ledger_dir=node_dir / "ledger",
        manifest_path=Path(__file__).resolve().parent.parent / "model-package" / "model-package.json",
        keys_dir=node_dir / "keys",
        runtime_label=f"poc-fixture-backend(mock_mesh_node.py) via {name}",
        runtime_digest="0" * 64,
        role=role,
        node_id=node_id,
    )
    server = run_sidecar(
        listen_host="127.0.0.1",
        listen_port=listen_port,
        upstream_base=f"http://127.0.0.1:{upstream_port}",
        state=state,
    )
    threading.Thread(target=server.serve_forever, daemon=True).start()
    _wait_for(f"http://127.0.0.1:{listen_port}/v1/models")
    return server, state


def _exchange_id(capsule: dict) -> str:
    return capsule["model_attestation"]["compute_attestation"]["x-mesh-poc-v1"]["serving_provenance"]["exchange_id"]


def _write_bundle(out_dir: Path, name: str, capsules: list[dict], reconciled: list, counts: dict) -> Path:
    path = out_dir / f"{name}.json"
    path.write_text(
        json.dumps(
            {
                "run": name,
                "capsules": capsules,
                "reconciliation": [
                    {
                        "key": r.key,
                        "state": r.state.value,
                        "requester_digest": r.requester_digest,
                        "counterparty_digest": r.counterparty_digest,
                        "detail": r.detail,
                    }
                    for r in reconciled
                ],
                "fold": counts,
                "fold_formatted": format_fold(counts),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return path


def run_a_mesh_provider(out_dir: Path, log: list[str]) -> tuple[dict, dict]:
    """RUN A: both halves exist (Path 2). Returns (requester_capsule, provider_capsule)."""
    mock = _start_mock_node(MOCK_PORT)
    provider_server, provider_state = _start_sidecar(
        out_dir=out_dir, name="run-a-provider", role=ROLE_PROVIDER, node_id="provider-node-1",
        listen_port=PROVIDER_SIDECAR_PORT, upstream_port=MOCK_PORT,
    )
    requester_server, requester_state = _start_sidecar(
        out_dir=out_dir, name="run-a-requester", role=ROLE_REQUESTER, node_id="requester-node-1",
        listen_port=REQUESTER_SIDECAR_PORT_CHAINED, upstream_port=PROVIDER_SIDECAR_PORT,
    )
    status, resp = _post_chat(REQUESTER_SIDECAR_PORT_CHAINED, "RUN A -- mesh provider exists")
    log.append(f"[run-a] status={status} response_id={resp.get('id')}")

    requester_capsule = requester_state.emitted[-1]
    provider_capsule = provider_state.emitted[-1]
    assert _exchange_id(requester_capsule) == _exchange_id(provider_capsule), (
        "both halves must correlate on the same exchange_id"
    )

    results = reconcile([requester_capsule], [provider_capsule], key_fn=_exchange_id)
    counts = fold(results)
    log.append(f"[run-a] reconciliation fold: {format_fold(counts)}")
    assert results[0].state == ReconciliationState.MATCHED, "RUN A must reconcile as matched"

    _write_bundle(out_dir, "run_a_mesh_provider", [requester_capsule, provider_capsule], results, counts)

    requester_server.shutdown()
    provider_server.shutdown()
    mock.shutdown()
    return requester_capsule, provider_capsule


def run_b_plain_api(out_dir: Path, log: list[str]) -> dict:
    """RUN B: no provider half. Returns the requester_capsule."""
    mock = _start_mock_node(MOCK_PORT + 10)
    requester_server, requester_state = _start_sidecar(
        out_dir=out_dir, name="run-b-requester", role=ROLE_REQUESTER, node_id="requester-node-1",
        listen_port=REQUESTER_SIDECAR_PORT_PLAIN, upstream_port=MOCK_PORT + 10,
    )
    status, resp = _post_chat(REQUESTER_SIDECAR_PORT_PLAIN, "RUN B -- plain API endpoint, no producer")
    log.append(f"[run-b] status={status} response_id={resp.get('id')}")

    requester_capsule = requester_state.emitted[-1]
    # No counterparty producer ran at all -- nothing to reconcile against.
    results = reconcile([requester_capsule], [], key_fn=_exchange_id)
    counts = fold(results)
    log.append(f"[run-b] reconciliation fold: {format_fold(counts)}")
    assert results[0].state == ReconciliationState.REQUESTER_ONLY, "RUN B must reconcile as requester_only (not present)"

    _write_bundle(out_dir, "run_b_plain_api", [requester_capsule], results, counts)

    requester_server.shutdown()
    mock.shutdown()
    return requester_capsule


def run_c_spoofed(out_dir: Path, harness_capsule: dict, log: list[str]) -> dict:
    """RUN C: the METR vector. A second record of RUN A's exchange, built as
    a downstream transcript would show it, with the response altered after
    the fact. Reconciled against the harness's OWN sealed record of what
    actually executed (harness_capsule, from RUN A)."""
    import hashlib

    from capsule_sidecar import digest_json

    downstream_node_dir = out_dir / "run-c-downstream"
    downstream_state = default_state(
        ledger_dir=downstream_node_dir / "ledger",
        manifest_path=Path(__file__).resolve().parent.parent / "model-package" / "model-package.json",
        keys_dir=downstream_node_dir / "keys",
        runtime_label="downstream-transcript-reseal (simulated post-hoc edit)",
        runtime_digest="1" * 64,
        role=ROLE_REQUESTER,
        node_id="downstream-transcript",
    )
    from capsule_sidecar import build_capsule, exchange_id_from_response

    real_exchange_id = _exchange_id(harness_capsule)
    spoofed_response = {
        "id": real_exchange_id,  # SAME exchange_id -- this is a claim about the SAME call
        "object": "chat.completion",
        "choices": [
            {"index": 0, "message": {"role": "assistant", "content": "SPOOFTEST"}, "finish_reason": "stop"}
        ],
    }
    xid, source = exchange_id_from_response(spoofed_response)
    downstream_capsule = build_capsule(
        downstream_state,
        client_nonce="deadbeef" * 4,
        client_nonce_source="client_supplied",
        request_json={"model": MODEL_ID, "messages": [{"role": "user", "content": "RUN A -- mesh provider exists"}]},
        request_digest=hashlib.sha256(b"RUN A -- mesh provider exists").hexdigest(),
        status="confirmed",
        response_digest=digest_json(spoofed_response),
        verdict_class="executed",
        disposition_decision="accept",
        latency_ms=1.0,
        exchange_id=xid,
        exchange_id_source=source,
    )

    results = reconcile([harness_capsule], [downstream_capsule], key_fn=_exchange_id)
    counts = fold(results)
    log.append(f"[run-c] reconciliation fold: {format_fold(counts)}")
    assert results[0].state == ReconciliationState.CONTRADICTED, (
        "RUN C's spoofed downstream record must reconcile as contradicted "
        "against the harness's own sealed record of what actually executed"
    )

    _write_bundle(out_dir, "run_c_spoofed", [harness_capsule, downstream_capsule], results, counts)
    return downstream_capsule


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", default=str(Path.home() / "dev" / "asg" / "_work" / "evaluator-bilateral"))
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)

    log: list[str] = []

    def out(line: str) -> None:
        print(line)
        log.append(line)

    out("=" * 72)
    out("evaluator-bilateral harness capture -- three runs, reconciled")
    out("Path 2 (capsule_sidecar.py) against mock_mesh_node.py -- see module")
    out("docstring 'WHICH MESH PATH THIS EXERCISES' before citing this run.")
    out("=" * 72)

    out("")
    out("RUN A -- mesh provider exists (both halves sealed)")
    requester_capsule_a, provider_capsule_a = run_a_mesh_provider(out_dir, log)
    out(f"  requester capsule_id: {requester_capsule_a['capsule_id']}")
    out(f"  provider  capsule_id: {provider_capsule_a['capsule_id']}")
    out(f"  exchange_id (shared): {_exchange_id(requester_capsule_a)}")

    out("")
    out("RUN B -- plain API endpoint (no provider half)")
    requester_capsule_b = run_b_plain_api(out_dir, log)
    out(f"  requester capsule_id: {requester_capsule_b['capsule_id']}")

    out("")
    out("RUN C -- METR spoofed-tool-call vector (reconciled against RUN A's harness capsule)")
    downstream_capsule_c = run_c_spoofed(out_dir, requester_capsule_a, log)
    out(f"  downstream (spoofed) capsule_id: {downstream_capsule_c['capsule_id']}")

    (out_dir / "transcript.txt").write_text("\n".join(log) + "\n")
    out("")
    out(f"Bundles + transcript written to {out_dir}")
    out("")
    out("All three runs reconciled to the state each is supposed to reach.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
