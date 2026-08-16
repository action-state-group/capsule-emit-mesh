"""End-to-end nonce demo test.

Runs run_demo.py as a subprocess (mock mesh-llm node + sidecar, no live mesh
dependency) and asserts both client_nonce_source labels appear in the output.
Using subprocess avoids the import-ordering problem between this file and
test_forwarded_copy_and_keys.py, which installs stub modules at import time.
"""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_nonce_end_to_end_both_labels_present():
    """run_demo.py emits records with client_supplied and sidecar_generated_fallback."""
    result = subprocess.run(
        [sys.executable, str(ROOT / "run_demo.py")],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
        timeout=30,
    )
    assert result.returncode == 0, (
        f"run_demo.py exited {result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    out = result.stdout

    # Both labels must appear in the per-capsule verification lines.
    assert "client_nonce_source=client_supplied" in out, (
        "client_supplied not found in demo output -- nonce header may not be forwarded"
    )
    assert "client_nonce_source=sidecar_generated_fallback" in out, (
        "sidecar_generated_fallback not found in demo output -- fallback path not demonstrated"
    )

    # Summary counts must reflect the split (4 supplied, 1 fallback).
    assert "N client_nonce_source=client_supplied: 4" in out, (
        "expected 4 client_supplied in summary"
    )
    assert "N client_nonce_source=sidecar_generated_fallback: 1" in out, (
        "expected 1 sidecar_generated_fallback in summary"
    )

    # Overall demo must pass its own chain + verify checks.
    assert "all capsules verify() ok AND chain-consistent: True" in out, (
        "demo reported a verification failure"
    )
