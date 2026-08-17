#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
capsule-emit-mesh benchmark harness — A/F matrix (PR 7).

Implements the benchmark configuration matrix from Mesh-LLM/mesh-llm#1332
§"Benchmark configurations":

  A  no plugin / sidecar installed           ← RUNS NOW (mock backend)
  B  plugin installed, lifecycle/body grants disabled
  C  plugin active, digest_only, no ledger
  D  plugin active, full mode, signing + ledger
  E  full mode, anchoring queued but isolated
  F  capsule_sidecar.py (reverse-proxy)      ← RUNS NOW (mock backend)

B–E require the native Rust plugin (#1331/#1332 Phase 3); stubs are emitted
in the output with their preconditions.

USAGE
-----
  cd capsule-emit-mesh          # repo root
  python3 bench/run_benchmark.py

  # options
  python3 bench/run_benchmark.py --configs A F   # specific configs
  python3 bench/run_benchmark.py --reps 50       # samples per cell
  python3 bench/run_benchmark.py --output bench/results/my-run.json
  python3 bench/run_benchmark.py --no-concurrency  # skip concurrency 4/16

OUTPUTS
-------
  bench/results/<timestamp>-benchmark.json   machine-readable results
  stdout                                     progress + summary table

ENVIRONMENT LABELLING
---------------------
Every result file carries a full environment stanza (OS, CPU, RAM, Python,
package versions, git SHA, timestamp).  An unlabelled benchmark result is a
claim, not a measurement — these numbers get quoted back.
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures
import hashlib
import json
import os
import platform
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ── repo root on sys.path so we can import mock_mesh_node / capsule_sidecar ──
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

import mock_mesh_node
from capsule_sidecar import default_state, run_sidecar

SCHEMA_VERSION = "capsule-emit-mesh-benchmark/v1"

# ── workload definitions ──────────────────────────────────────────────────────

MODEL = "capsule-emit-poc/tiny-fixture-model:Q4_K_XL"

# Synthetic base64 blob for multimodal fixture (1 KiB of zeros, no private data).
_FAKE_IMG_B64 = base64.b64encode(b"\x00" * 1024).decode()

WORKLOADS: dict[str, dict[str, Any]] = {
    "short_nonstream": {
        "description": "Short non-streaming chat completion",
        "stream": False,
        "payload": {
            "model": MODEL,
            "messages": [{"role": "user", "content": "What is 2+2?"}],
            "stream": False,
            "max_tokens": 50,
            "temperature": "0.0",  # decimal string per PR 2 number rule
        },
    },
    "short_stream": {
        "description": (
            "Short prompt, stream=true "
            "(mock backend returns JSON not SSE; "
            "measures sidecar streaming-path overhead; "
            "real SSE throughput requires mesh-llm real node)"
        ),
        "stream": True,
        "payload": {
            "model": MODEL,
            "messages": [{"role": "user", "content": "Count to five."}],
            "stream": True,
            "max_tokens": 100,
        },
    },
    "long_context": {
        "description": "Long-context request (~2.5 KiB prompt body)",
        "stream": False,
        "payload": {
            "model": MODEL,
            "messages": [
                {"role": "system", "content": "You are a helpful assistant. " + "Background context: " + "A" * 900},
                {"role": "user", "content": "Summarize the above context in one sentence. " + "B" * 400},
            ],
            "stream": False,
            "max_tokens": 50,
        },
    },
    "tool_calling": {
        "description": "Tool-calling request with nested schemas",
        "stream": False,
        "payload": {
            "model": MODEL,
            "messages": [{"role": "user", "content": "What is the weather in Paris?"}],
            "stream": False,
            "max_tokens": 100,
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": "get_weather",
                        "description": "Get weather for a city",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "city": {"type": "string", "description": "City name"},
                                "units": {
                                    "type": "string",
                                    "enum": ["celsius", "fahrenheit"],
                                },
                                "options": {
                                    "type": "object",
                                    "properties": {
                                        "include_forecast": {"type": "boolean"},
                                        "days": {"type": "integer", "minimum": 1, "maximum": 7},
                                    },
                                },
                            },
                            "required": ["city"],
                        },
                    },
                }
            ],
        },
    },
    "multimodal_shaped": {
        "description": (
            "Multimodal-shaped request (synthetic 1 KiB image_url data URI, "
            "no private data)"
        ),
        "stream": False,
        "payload": {
            "model": MODEL,
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "Describe this image."},
                        {
                            "type": "image_url",
                            "image_url": {
                                "url": f"data:image/png;base64,{_FAKE_IMG_B64}",
                                "detail": "auto",
                            },
                        },
                    ],
                }
            ],
            "stream": False,
            "max_tokens": 100,
        },
    },
    "backend_error": {
        "description": (
            "Backend error path — guardrail refusal trigger. "
            "Expected 400 from mock; sidecar records as errored/failed capsule."
        ),
        "stream": False,
        "expect_error": True,
        "payload": {
            "model": MODEL,
            "messages": [
                {"role": "user", "content": "TRIGGER_GUARDRAIL_REFUSAL benchmark test probe"}
            ],
            "stream": False,
            "max_tokens": 50,
        },
    },
}

CONCURRENCY_LEVELS = [1, 4, 16]
WARMUP_REPS = 5
DEFAULT_REPS = 30


# ── percentile helper (no numpy dep) ─────────────────────────────────────────

def percentile(data: list[float], p: float) -> float:
    """Linear interpolation percentile (nearest-rank-ish, same as numpy default)."""
    if not data:
        return float("nan")
    sorted_d = sorted(data)
    n = len(sorted_d)
    k = (n - 1) * p / 100.0
    lo, hi = int(k), min(int(k) + 1, n - 1)
    return sorted_d[lo] + (sorted_d[hi] - sorted_d[lo]) * (k - lo)


def summarise(samples_ms: list[float]) -> dict[str, Any]:
    if not samples_ms:
        return {"n": 0}
    s = sorted(samples_ms)
    mean = sum(s) / len(s)
    variance = sum((x - mean) ** 2 for x in s) / len(s)
    return {
        "n": len(s),
        "p50_ms": round(percentile(s, 50), 3),
        "p95_ms": round(percentile(s, 95), 3),
        "p99_ms": round(percentile(s, 99), 3),
        "mean_ms": round(mean, 3),
        "min_ms": round(s[0], 3),
        "max_ms": round(s[-1], 3),
        "stddev_ms": round(variance ** 0.5, 3),
    }


# ── network helpers ───────────────────────────────────────────────────────────

def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for_port(host: str, port: int, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            urllib.request.urlopen(f"http://{host}:{port}/v1/models", timeout=0.5)
            return
        except Exception:
            time.sleep(0.05)
    raise TimeoutError(f"http://{host}:{port} did not become ready in {timeout}s")


def send_request(url: str, payload: dict[str, Any]) -> tuple[float, int, bool]:
    """Return (latency_ms, http_status, success)."""
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp.read()
            status = resp.status
    except urllib.error.HTTPError as exc:
        exc.read()
        status = exc.code
    t1 = time.perf_counter()
    return (t1 - t0) * 1000.0, status, True


# ── environment capture ───────────────────────────────────────────────────────

def capture_env() -> dict[str, Any]:
    env: dict[str, Any] = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "machine": platform.machine(),
        "node": platform.node(),
        "os": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "platform": platform.platform(),
        "processor": platform.processor(),
        "python_version": sys.version,
        "python_impl": platform.python_implementation(),
        "cpu_count_logical": os.cpu_count(),
    }

    # macOS hardware identifiers
    for key, cmd in [
        ("cpu_brand", ["sysctl", "-n", "machdep.cpu.brand_string"]),
        ("cpu_count_physical", ["sysctl", "-n", "hw.physicalcpu"]),
        ("cpu_count_logical_sysctl", ["sysctl", "-n", "hw.logicalcpu"]),
        ("memory_bytes_str", ["sysctl", "-n", "hw.memsize"]),
        ("hw_model", ["sysctl", "-n", "hw.model"]),
    ]:
        try:
            val = subprocess.check_output(cmd, text=True, timeout=5).strip()
            env[key] = val
        except Exception:
            pass

    if "memory_bytes_str" in env:
        try:
            mem = int(env["memory_bytes_str"])
            env["memory_bytes"] = mem
            env["memory_gib"] = round(mem / (1024 ** 3), 1)
        except ValueError:
            pass
        del env["memory_bytes_str"]

    # git SHA of the repo being benchmarked
    try:
        env["git_sha"] = subprocess.check_output(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
            text=True, timeout=5,
        ).strip()
        env["git_branch"] = subprocess.check_output(
            ["git", "-C", str(ROOT), "rev-parse", "--abbrev-ref", "HEAD"],
            text=True, timeout=5,
        ).strip()
    except Exception:
        env["git_sha"] = "unknown"

    # installed package versions (relevant subset)
    try:
        raw = subprocess.check_output(
            [sys.executable, "-m", "pip", "freeze"], text=True, timeout=15
        )
        env["pip_freeze"] = [
            line for line in raw.strip().splitlines()
            if any(
                pkg in line.lower()
                for pkg in [
                    "agent-action-capsule", "capsule-emit", "scitt-cose",
                    "cbor2", "cryptography", "aiohttp", "httpx",
                ]
            )
        ]
    except Exception:
        env["pip_freeze"] = []

    # benchmark script SHA for result provenance
    try:
        script_bytes = Path(__file__).read_bytes()
        env["harness_sha256"] = hashlib.sha256(script_bytes).hexdigest()[:16]
    except Exception:
        pass

    return env


# ── benchmark runner ──────────────────────────────────────────────────────────

def run_workloads(
    base_url: str,
    reps: int,
    concurrency_levels: list[int],
    warmup_reps: int,
) -> dict[str, Any]:
    """Run all workloads against base_url. Returns nested results dict."""
    results: dict[str, Any] = {}
    endpoint = f"{base_url}/v1/chat/completions"

    for wl_name, wl in WORKLOADS.items():
        results[wl_name] = {
            "description": wl["description"],
            "expect_error": wl.get("expect_error", False),
            "stream_flag": wl.get("stream", False),
            "concurrency": {},
        }
        payload = wl["payload"]

        for concurrency in concurrency_levels:
            print(f"    workload={wl_name} concurrency={concurrency} ...", end="", flush=True)

            # warmup
            for _ in range(warmup_reps):
                try:
                    send_request(endpoint, payload)
                except Exception:
                    pass

            samples_ms: list[float] = []
            errors: list[str] = []

            if concurrency == 1:
                for _ in range(reps):
                    try:
                        lat, status, _ = send_request(endpoint, payload)
                        samples_ms.append(lat)
                    except Exception as exc:
                        errors.append(str(exc))
            else:
                def _one_req(_: int) -> tuple[float, int] | str:
                    try:
                        lat, status, _ = send_request(endpoint, payload)
                        return (lat, status)
                    except Exception as exc:
                        return str(exc)

                with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
                    futures = [pool.submit(_one_req, i) for i in range(reps)]
                    for f in concurrent.futures.as_completed(futures):
                        result = f.result()
                        if isinstance(result, str):
                            errors.append(result)
                        else:
                            samples_ms.append(result[0])

            stats = summarise(samples_ms)
            stats["warmup_reps"] = warmup_reps
            stats["error_count"] = len(errors)
            if errors:
                stats["error_sample"] = errors[:3]

            results[wl_name]["concurrency"][str(concurrency)] = stats
            print(f" p50={stats.get('p50_ms', 'n/a')}ms p95={stats.get('p95_ms', 'n/a')}ms p99={stats.get('p99_ms', 'n/a')}ms")

    return results


# ── config A ──────────────────────────────────────────────────────────────────

def run_config_a(reps: int, concurrency_levels: list[int]) -> dict[str, Any]:
    """Config A: no plugin/sidecar — direct mock backend."""
    mock_port = find_free_port()
    mock_server = mock_mesh_node.ThreadingHTTPServer(
        ("127.0.0.1", mock_port), mock_mesh_node.Handler
    )
    mock_thread = threading.Thread(target=mock_server.serve_forever, daemon=True)
    mock_thread.start()
    wait_for_port("127.0.0.1", mock_port)

    print(f"  [A] mock node on :{mock_port}")
    base_url = f"http://127.0.0.1:{mock_port}"

    try:
        workload_results = run_workloads(
            base_url,
            reps=reps,
            concurrency_levels=concurrency_levels,
            warmup_reps=WARMUP_REPS,
        )
    finally:
        mock_server.shutdown()

    return {
        "config": "A",
        "description": (
            "No plugin installed. Direct request/response with no "
            "interceptor overhead. Baseline for all other configs."
        ),
        "backend": "mock_mesh_node.py (in-process, deterministic JSON fixture)",
        "sidecar": None,
        "reps_per_cell": reps,
        "warmup_reps": WARMUP_REPS,
        "workloads": workload_results,
    }


# ── config F ──────────────────────────────────────────────────────────────────

def run_config_f(reps: int, concurrency_levels: list[int]) -> dict[str, Any]:
    """Config F: capsule_sidecar.py reverse proxy in front of mock backend."""
    mock_port = find_free_port()
    sidecar_port = find_free_port()

    mock_server = mock_mesh_node.ThreadingHTTPServer(
        ("127.0.0.1", mock_port), mock_mesh_node.Handler
    )
    mock_thread = threading.Thread(target=mock_server.serve_forever, daemon=True)
    mock_thread.start()
    wait_for_port("127.0.0.1", mock_port)

    with tempfile.TemporaryDirectory(prefix="capsule-bench-f-ledger-") as tmp_ledger:
        # Runtime digest: sha256 of the mock node source (same as run_demo.py convention).
        runtime_artifact = Path(mock_mesh_node.__file__).read_bytes()
        runtime_digest = hashlib.sha256(runtime_artifact).hexdigest()

        state = default_state(
            ledger_dir=Path(tmp_ledger),
            manifest_path=ROOT / "model-package" / "model-package.json",
            keys_dir=ROOT / "keys",
            runtime_label="mock-mesh-node-bench-fixture",
            runtime_digest=runtime_digest,
        )
        sidecar_server = run_sidecar(
            listen_host="127.0.0.1",
            listen_port=sidecar_port,
            upstream_base=f"http://127.0.0.1:{mock_port}",
            state=state,
        )
        sidecar_thread = threading.Thread(target=sidecar_server.serve_forever, daemon=True)
        sidecar_thread.start()
        wait_for_port("127.0.0.1", sidecar_port)

        print(f"  [F] mock node on :{mock_port} | sidecar on :{sidecar_port}")
        base_url = f"http://127.0.0.1:{sidecar_port}"

        try:
            workload_results = run_workloads(
                base_url,
                reps=reps,
                concurrency_levels=concurrency_levels,
                warmup_reps=WARMUP_REPS,
            )
        finally:
            sidecar_server.shutdown()
            mock_server.shutdown()

    return {
        "config": "F",
        "description": (
            "Previous reverse-proxy sidecar (capsule_sidecar.py) in front of "
            "mock backend. Informative comparison per #1332 — not the target "
            "architecture (that is the native plugin, configs B–E). "
            "Overhead vs A = request hashing + JSON canonicalisation + "
            "COSE signing + ledger append, all on the Python hot path."
        ),
        "backend": "mock_mesh_node.py (in-process, deterministic JSON fixture)",
        "sidecar": "capsule_sidecar.py (ThreadingHTTPServer, same process)",
        "sidecar_note": (
            "Streaming workload (short_stream, stream=true): mock backend "
            "returns JSON not SSE; sidecar's streaming path sees zero SSE "
            "chunks and re-synthesises an empty SSE frame sequence. "
            "Measures streaming-path IPC + signing overhead but not "
            "token-cadence throughput (real SSE requires mesh-llm real node)."
        ),
        "reps_per_cell": reps,
        "warmup_reps": WARMUP_REPS,
        "workloads": workload_results,
    }


# ── B–E stubs ─────────────────────────────────────────────────────────────────

B_E_STUBS: dict[str, dict[str, Any]] = {
    "B": {
        "config": "B",
        "status": "stub",
        "description": (
            "Plugin installed with lifecycle/body grants disabled. "
            "Measures generic mesh-llm plugin-hook overhead with no "
            "capsule work performed — isolates IPC entry cost."
        ),
        "preconditions": [
            "Native Rust capsule-emit plugin built per #1332 (Phase 3 P1/P2).",
            "mesh-llm ≥ 0.78.0 with #1331 plugin lifecycle API.",
            "Plugin installed via mesh-llm plugin mechanism (no fork).",
            "Plugin manifest declares mesh.openai.exchange.v1 but grants "
            "body/lifecycle access disabled in host config.",
            "Same GGUF model and hardware as A for apples-to-apples delta.",
        ],
        "run_instructions": (
            "mesh-llm serve --gguf <model.gguf> --port 9337 "
            "--plugin-config capsule-emit-disabled-grants.toml; "
            "python3 bench/run_benchmark.py --configs B --upstream 127.0.0.1:9337"
        ),
    },
    "C": {
        "config": "C",
        "status": "stub",
        "description": (
            "Plugin active, digest_only evidence mode, ledger persistence "
            "disabled. Measures request hashing + COSE signing without "
            "filesystem I/O — isolates crypto path cost."
        ),
        "preconditions": [
            "Preconditions B, plus:",
            "Plugin body/lifecycle grants enabled.",
            "Plugin config: evidence_mode=digest_only, ledger disabled.",
        ],
    },
    "D": {
        "config": "D",
        "status": "stub",
        "description": (
            "Plugin active, full evidence mode, local signing and ledger "
            "persistence enabled. Primary production-like configuration "
            "and the pass/conditional/redesign/stop decision gate per #1332."
        ),
        "preconditions": [
            "Preconditions C, plus:",
            "Plugin config: evidence_mode=full, ledger=<dir>.",
            "Ledger dir on the same disk class as production (NVMe/SSD).",
            "Measure fsync latency separately.",
        ],
    },
    "E": {
        "config": "E",
        "status": "stub",
        "description": (
            "Full mode with anchoring enabled, but network submission "
            "isolated behind the durable retry queue. Measures anchoring "
            "queue write overhead while keeping network latency out of "
            "the critical path."
        ),
        "preconditions": [
            "Preconditions D, plus:",
            "Plugin config: anchoring_enabled=true, anchor_url=<isolated-or-mock>.",
            "Network submission isolated: either a mock anchor endpoint "
            "that accepts and drops, or the real anchor with a loopback "
            "firewall rule so submissions queue but never complete.",
            "Verify anchor queue depth rises and no requests are retried "
            "into the benchmark window.",
        ],
    },
}


# ── delta table ───────────────────────────────────────────────────────────────

def print_delta_table(results_a: dict[str, Any], results_f: dict[str, Any]) -> None:
    """Print a concise p50/p95/p99 comparison: A vs F."""
    print("\n── A vs F delta table (concurrency=1) ──────────────────────────────")
    fmt = "{:<22} {:>10} {:>10} {:>10}  {:>10} {:>10} {:>10}  {:>10}"
    print(fmt.format("workload", "A p50", "A p95", "A p99", "F p50", "F p95", "F p99", "Δ p50"))
    print("-" * 95)
    for wl in WORKLOADS:
        a_cell = results_a["workloads"].get(wl, {}).get("concurrency", {}).get("1", {})
        f_cell = results_f["workloads"].get(wl, {}).get("concurrency", {}).get("1", {})
        a50 = a_cell.get("p50_ms", float("nan"))
        a95 = a_cell.get("p95_ms", float("nan"))
        a99 = a_cell.get("p99_ms", float("nan"))
        f50 = f_cell.get("p50_ms", float("nan"))
        f95 = f_cell.get("p95_ms", float("nan"))
        f99 = f_cell.get("p99_ms", float("nan"))
        try:
            delta = f50 - a50
            delta_str = f"+{delta:.3f}" if delta >= 0 else f"{delta:.3f}"
        except TypeError:
            delta_str = "n/a"
        print(fmt.format(
            wl[:22],
            f"{a50:.3f}ms" if isinstance(a50, float) and a50 == a50 else "n/a",
            f"{a95:.3f}ms" if isinstance(a95, float) and a95 == a95 else "n/a",
            f"{a99:.3f}ms" if isinstance(a99, float) and a99 == a99 else "n/a",
            f"{f50:.3f}ms" if isinstance(f50, float) and f50 == f50 else "n/a",
            f"{f95:.3f}ms" if isinstance(f95, float) and f95 == f95 else "n/a",
            f"{f99:.3f}ms" if isinstance(f99, float) and f99 == f99 else "n/a",
            delta_str,
        ))
    print()


# ── main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="capsule-emit-mesh benchmark harness — A/F matrix (PR 7)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--configs",
        nargs="+",
        default=["A", "F"],
        choices=["A", "F"],
        help="configs to run (default: A F; B–E stub only, require Rust plugin)",
    )
    parser.add_argument(
        "--reps",
        type=int,
        default=DEFAULT_REPS,
        help=f"measurement repetitions per cell (default: {DEFAULT_REPS})",
    )
    parser.add_argument(
        "--no-concurrency",
        action="store_true",
        help="only run concurrency=1 (skip 4 and 16)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="output JSON path (default: bench/results/<timestamp>-benchmark.json)",
    )
    args = parser.parse_args()

    concurrency_levels = [1] if args.no_concurrency else CONCURRENCY_LEVELS

    if args.output is None:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        args.output = ROOT / "bench" / "results" / f"{ts}-benchmark.json"

    args.output.parent.mkdir(parents=True, exist_ok=True)

    print("capsule-emit-mesh benchmark harness")
    print(f"  configs:     {args.configs}")
    print(f"  reps/cell:   {args.reps} + {WARMUP_REPS} warmup")
    print(f"  concurrency: {concurrency_levels}")
    print(f"  output:      {args.output}")
    print()

    print("Capturing environment ...")
    env = capture_env()
    print(f"  machine: {env.get('hw_model', env.get('platform', 'unknown'))}")
    print(f"  cpu:     {env.get('cpu_brand', env.get('processor', 'unknown'))}")
    print(f"  ram:     {env.get('memory_gib', '?')} GiB")
    print(f"  python:  {env.get('python_version', '?').split()[0]}")
    print(f"  git:     {env.get('git_sha', 'unknown')[:12]}")
    print()

    output: dict[str, Any] = {
        "schema": SCHEMA_VERSION,
        "generated_utc": env["timestamp_utc"],
        "environment": env,
        "configs": {},
    }

    # always include B–E stubs
    for letter, stub in B_E_STUBS.items():
        output["configs"][letter] = stub

    if "A" in args.configs:
        print("Running config A (no sidecar / direct mock) ...")
        output["configs"]["A"] = run_config_a(
            reps=args.reps,
            concurrency_levels=concurrency_levels,
        )
        print()

    if "F" in args.configs:
        print("Running config F (capsule_sidecar.py) ...")
        output["configs"]["F"] = run_config_f(
            reps=args.reps,
            concurrency_levels=concurrency_levels,
        )
        print()

    # delta table if both ran
    if "A" in args.configs and "F" in args.configs:
        print_delta_table(output["configs"]["A"], output["configs"]["F"])

    with open(args.output, "w") as fh:
        json.dump(output, fh, indent=2)
    print(f"Results written → {args.output}")


if __name__ == "__main__":
    main()
