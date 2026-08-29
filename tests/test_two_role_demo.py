# SPDX-License-Identifier: Apache-2.0
"""CI-enforced regression test for the 2-role adversarial harness.

Runs two_role_demo.py as a subprocess (real library environment, same
pattern as test_bilateral_demo.py's test_bilateral_demo_e2e) so the exact
harness code the live runbook uses -- send_bilateral_request.py,
checkpoint_ledger.py, stranger_verify_bundle.py -- is exercised end-to-end
on every CI run, even though the LIVE two-Mac proof (real mesh-llm host,
real admission-policy plugin) cannot run here.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_two_role_demo_e2e():
    result = subprocess.run(
        [sys.executable, str(Path(__file__).resolve().parent.parent / "two_role_demo.py")],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, (
        f"two_role_demo.py exited {result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "All acceptance gates passed" in result.stdout
    assert "cross_party_rung=full_bilateral" in result.stdout
    assert "tamper-check 1/2: TAMPER DETECTED = True" in result.stdout
    assert "tamper-check 2/2: TAMPER DETECTED = True" in result.stdout
