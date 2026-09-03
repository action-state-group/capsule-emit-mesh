# SPDX-License-Identifier: Apache-2.0
"""mac_hardware_inventory.py: PATH (a), the Mac-only hardware_inventory rung.

Focus: (1) a live capture on this dev Mac is well-formed, labeled `os_measured`,
and never leaks the raw serial/platform UUID; (2) every way the capture can fail
(non-macOS, system_profiler unavailable, malformed output, no serial) returns
None -- the mutant this module exists to prevent is a fabricated/blank record
standing in for an honest "absent"."""
from __future__ import annotations

import hashlib
import json
import platform
import subprocess

import pytest

import mac_hardware_inventory as mhi
from mac_hardware_inventory import GRADE_OS_MEASURED, capture_mac_hardware_inventory


@pytest.mark.skipif(platform.system() != "Darwin", reason="live capture only runs on macOS")
def test_live_capture_on_this_mac_is_well_formed():
    inventory = capture_mac_hardware_inventory()
    assert inventory is not None, "system_profiler must be available in this dev environment"
    block = inventory.to_capsule_block()

    assert block["source"] == "os_reported"
    assert block["capture_method"] == "system_profiler"
    assert block["grade"] == GRADE_OS_MEASURED
    assert block["model_identifier"]
    assert block["chip"]
    assert isinstance(block["memory_bytes"], int) and block["memory_bytes"] > 0
    assert isinstance(block["cpu_cores"]["total"], int) and block["cpu_cores"]["total"] > 0
    assert len(block["serial_digest"]) == 64  # sha256 hex
    int(block["serial_digest"], 16)  # valid hex


def test_serial_digest_recomputes_from_the_real_serial_but_never_carries_it():
    inventory = capture_mac_hardware_inventory()
    if inventory is None:
        pytest.skip("no macOS hardware available to capture")
    profile = mhi._system_profiler()
    real_serial = profile["SPHardwareDataType"][0]["serial_number"]
    assert inventory.serial_digest == hashlib.sha256(real_serial.encode()).hexdigest()

    block_json = json.dumps(inventory.to_capsule_block())
    assert real_serial not in block_json, "raw serial must never appear in the sealed block"
    platform_uuid = profile["SPHardwareDataType"][0].get("platform_UUID")
    if platform_uuid:
        assert platform_uuid not in block_json, "platform UUID must never appear in the sealed block"


def test_capsule_block_has_no_field_capable_of_carrying_the_raw_serial():
    """Structural guard, independent of what this particular machine's serial
    looks like: the block's key set is closed and none of them is a raw-serial or
    platform-UUID field."""
    inventory = capture_mac_hardware_inventory()
    if inventory is None:
        pytest.skip("no macOS hardware available to capture")
    block = inventory.to_capsule_block()
    forbidden_keys = {"serial_number", "serial", "platform_uuid", "platform_UUID", "provisioning_UDID"}
    assert forbidden_keys.isdisjoint(block.keys())


# --------------------------------------------------------------------------- mutant: absent, never fabricated


def test_non_macos_host_returns_none(monkeypatch):
    monkeypatch.setattr(mhi.platform, "system", lambda: "Linux")
    assert capture_mac_hardware_inventory() is None


def test_system_profiler_unavailable_returns_none(monkeypatch):
    monkeypatch.setattr(mhi.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(mhi, "_system_profiler", lambda: None)
    assert capture_mac_hardware_inventory() is None


def test_run_swallows_subprocess_failure_and_returns_none(monkeypatch):
    """`_run` itself never raises: a crashing/missing binary degrades to None,
    which is what makes `_system_profiler`/`_sysctl` honestly absent rather than
    an unhandled exception taking down the sidecar's serving path."""

    def _boom(*args, **kwargs):
        raise subprocess.SubprocessError("simulated system_profiler crash")

    monkeypatch.setattr(mhi.subprocess, "run", _boom)
    assert mhi._run(["system_profiler", "-json"]) is None


def test_system_profiler_crash_propagates_to_absent_capture(monkeypatch):
    monkeypatch.setattr(mhi.platform, "system", lambda: "Darwin")

    def _boom(*args, **kwargs):
        raise subprocess.SubprocessError("simulated system_profiler crash")

    monkeypatch.setattr(mhi.subprocess, "run", _boom)
    assert capture_mac_hardware_inventory() is None


def test_malformed_system_profiler_output_returns_none(monkeypatch):
    monkeypatch.setattr(mhi.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(mhi, "_system_profiler", lambda: {"unexpected": "shape"})
    assert capture_mac_hardware_inventory() is None


def test_missing_serial_returns_none_never_a_fabricated_digest(monkeypatch):
    monkeypatch.setattr(mhi.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(
        mhi,
        "_system_profiler",
        lambda: {
            "SPHardwareDataType": [{"machine_model": "Mac16,5"}],  # no serial_number key
            "SPSoftwareDataType": [{"os_version": "macOS 15.6 (24G84)", "system_integrity": "integrity_enabled"}],
            "SPDisplaysDataType": [],
        },
    )
    assert capture_mac_hardware_inventory() is None


def test_synthetic_capture_shape_and_sip_and_os_build_parsing(monkeypatch):
    """A fully synthetic, controlled profile -- proves the parsing logic (SIP
    boolean, os_version/build split, GPU core count) independent of whatever this
    particular dev Mac happens to report."""
    monkeypatch.setattr(mhi.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(
        mhi,
        "_system_profiler",
        lambda: {
            "SPHardwareDataType": [
                {
                    "machine_model": "Mac15,6",
                    "chip_type": "Apple M3 Max",
                    "serial_number": "SYNTHETIC0001",
                    "platform_UUID": "SYNTHETIC-UUID",
                    "boot_rom_version": "10151.140.19",
                }
            ],
            "SPSoftwareDataType": [
                {"os_version": "macOS 15.6 (24G84)", "system_integrity": "integrity_enabled"}
            ],
            "SPDisplaysDataType": [{"sppci_cores": "40"}],
        },
    )
    monkeypatch.setattr(
        mhi,
        "_sysctl",
        lambda: {
            "hw.model": "Mac15,6",
            "hw.memsize": "51539607552",
            "hw.ncpu": "16",
            "hw.perflevel0.physicalcpu": "12",
            "hw.perflevel1.physicalcpu": "4",
            "machdep.cpu.brand_string": "Apple M3 Max",
        },
    )
    monkeypatch.setattr(mhi, "_secure_boot_policy", lambda: "full")

    inventory = capture_mac_hardware_inventory()
    assert inventory is not None
    block = inventory.to_capsule_block()
    assert block["model_identifier"] == "Mac15,6"
    assert block["chip"] == "Apple M3 Max"
    assert block["cpu_cores"] == {"performance": 12, "efficiency": 4, "total": 16}
    assert block["gpu_cores"] == 40
    assert block["memory_bytes"] == 51539607552
    assert block["os_version"] == "macOS 15.6"
    assert block["os_build"] == "24G84"
    assert block["sip_enabled"] is True
    assert block["secure_boot_policy"] == "full"
    assert block["serial_digest"] == hashlib.sha256(b"SYNTHETIC0001").hexdigest()
    assert "SYNTHETIC0001" not in json.dumps(block)
    assert "SYNTHETIC-UUID" not in json.dumps(block)


def test_sip_disabled_reported_honestly(monkeypatch):
    monkeypatch.setattr(mhi.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(
        mhi,
        "_system_profiler",
        lambda: {
            "SPHardwareDataType": [{"machine_model": "Mac16,5", "serial_number": "X"}],
            "SPSoftwareDataType": [{"os_version": "macOS 15.6 (24G84)", "system_integrity": "integrity_disabled"}],
            "SPDisplaysDataType": [],
        },
    )
    monkeypatch.setattr(mhi, "_sysctl", lambda: {})
    monkeypatch.setattr(mhi, "_secure_boot_policy", lambda: None)
    inventory = capture_mac_hardware_inventory()
    assert inventory is not None
    assert inventory.to_capsule_block()["sip_enabled"] is False
