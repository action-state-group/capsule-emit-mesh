#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""mac_hardware_inventory -- rung 3a-adjacent PATH (a): as-complete-and-honest-as-
it-can-be hardware self-report for the Mac development fleet.

This is NOT the existing `os_measured` binary/runtime rung
(`plugins/capsule-producer/src/runtime_attest.rs`, README.md's "runtime/binary
attestation" table row) -- that measures the SERVING BINARY's kernel-reported
cdhash. This module measures the HOST HARDWARE the node runs on: what
`system_profiler`/`sysctl` say about the machine, sealed by the sidecar. Same
grade NAME (`os_measured`) because the honesty shape is identical -- "the OS says
so, independently of the process, but a root user can still lie to the OS" -- but
a DIFFERENT evidence slot (`hardware_inventory`, not `binary_attestation`). The
accountability tab renders them as separate rung cards; see
`capsule_accountability_tab.hardware_inventory_grade`.

No TPM2 PC is available this week (Steven, 2026-09-02) -- Mac only. The next rung
for Macs (an Apple Secure-Enclave-bound node key) would prove "this Mac signed",
not "what booted or ran" -- that is `hw_bound_key`, an orthogonal property, not a
measurement rung, and is not built here. App Attest/DeviceCheck need Apple
entitlements + Apple's server and are out of scope.

Privacy: the raw serial number and platform UUID are stable personal identifiers
and MUST NEVER appear in a capsule. Only `serial_digest = SHA-256(serial)` is
carried -- the operator can prove the preimage later if ever needed, but nothing
here can be correlated back to the serial without it.
"""
from __future__ import annotations

import hashlib
import json
import platform
import subprocess
from dataclasses import dataclass
from typing import Any, Optional

__all__ = [
    "HARDWARE_INVENTORY_SLOT",
    "GRADE_OS_MEASURED",
    "HardwareInventory",
    "capture_mac_hardware_inventory",
]

HARDWARE_INVENTORY_SLOT = "hardware_inventory"
GRADE_OS_MEASURED = "os_measured"

_SYSCTL_KEYS = (
    "hw.model",
    "hw.memsize",
    "hw.ncpu",
    "hw.perflevel0.physicalcpu",
    "hw.perflevel1.physicalcpu",
    "machdep.cpu.brand_string",
)


@dataclass
class HardwareInventory:
    """The per-node hardware_inventory block. `to_capsule_block()` is exactly what
    gets sealed -- never the raw serial/UUID, by construction (there is no field
    for them here)."""

    model_identifier: str
    chip: str
    cpu_cores_performance: Optional[int]
    cpu_cores_efficiency: Optional[int]
    cpu_cores_total: Optional[int]
    gpu_cores: Optional[int]
    memory_bytes: Optional[int]
    firmware_version: Optional[str]
    os_version: str
    os_build: Optional[str]
    sip_enabled: Optional[bool]
    secure_boot_policy: Optional[str]
    serial_digest: str

    def to_capsule_block(self) -> dict[str, Any]:
        return {
            "source": "os_reported",
            "capture_method": "system_profiler",
            "grade": GRADE_OS_MEASURED,
            "model_identifier": self.model_identifier,
            "chip": self.chip,
            "cpu_cores": {
                "performance": self.cpu_cores_performance,
                "efficiency": self.cpu_cores_efficiency,
                "total": self.cpu_cores_total,
            },
            "gpu_cores": self.gpu_cores,
            "memory_bytes": self.memory_bytes,
            "firmware_version": self.firmware_version,
            "os_version": self.os_version,
            "os_build": self.os_build,
            "sip_enabled": self.sip_enabled,
            "secure_boot_policy": self.secure_boot_policy,
            "serial_digest": self.serial_digest,
        }


def _run(cmd: list[str]) -> Optional[str]:
    try:
        out = subprocess.run(cmd, capture_output=True, timeout=10, check=True)
        return out.stdout.decode("utf-8", errors="replace")
    except (OSError, subprocess.SubprocessError):
        return None


def _sysctl() -> dict[str, str]:
    text = _run(["sysctl"] + list(_SYSCTL_KEYS))
    values: dict[str, str] = {}
    if not text:
        return values
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        values[key.strip()] = value.strip()
    return values


def _system_profiler() -> Optional[dict[str, Any]]:
    text = _run(["system_profiler", "SPHardwareDataType", "SPDisplaysDataType", "SPSoftwareDataType", "-json"])
    if not text:
        return None
    try:
        return json.loads(text)
    except ValueError:
        return None


def _secure_boot_policy() -> Optional[str]:
    """Best-effort, non-sudo read. `bputil -d` requires root on most machines, so
    this degrades to None (absent) rather than shelling out with elevated
    privileges the sidecar should never hold."""
    text = _run(["nvram", "94b73556-2197-4702-82a8-3e1337dafbfb:AppleSecureBootPolicy"])
    if not text:
        return None
    return text.strip() or None


def _int_or_none(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def capture_mac_hardware_inventory() -> Optional[HardwareInventory]:
    """Capture this Mac's hardware_inventory block. Returns None -- never a
    fabricated/default record -- when `system_profiler` is unavailable, fails, or
    this host is not macOS. The caller (the accountability tab / capsule sealer)
    must render an explicit `absent` state for None, never blank (the mutant this
    module's tests enforce)."""
    if platform.system() != "Darwin":
        return None

    profile = _system_profiler()
    if not profile:
        return None
    try:
        hw = profile["SPHardwareDataType"][0]
        sw = profile["SPSoftwareDataType"][0]
    except (KeyError, IndexError, TypeError):
        return None

    serial = hw.get("serial_number")
    if not serial:
        return None
    serial_digest = hashlib.sha256(serial.encode("utf-8")).hexdigest()

    sysctl_values = _sysctl()
    gpu_cores = None
    displays = profile.get("SPDisplaysDataType") or []
    if displays:
        gpu_cores = _int_or_none(displays[0].get("sppci_cores"))

    os_version_full = sw.get("os_version", "")
    os_build = None
    if "(" in os_version_full and os_version_full.endswith(")"):
        os_version, _, build = os_version_full.rpartition("(")
        os_version = os_version.strip()
        os_build = build.rstrip(")").strip()
    else:
        os_version = os_version_full

    system_integrity = sw.get("system_integrity")
    sip_enabled = None
    if system_integrity is not None:
        sip_enabled = system_integrity == "integrity_enabled"

    return HardwareInventory(
        model_identifier=sysctl_values.get("hw.model") or hw.get("machine_model", ""),
        chip=sysctl_values.get("machdep.cpu.brand_string") or hw.get("chip_type", ""),
        cpu_cores_performance=_int_or_none(sysctl_values.get("hw.perflevel0.physicalcpu")),
        cpu_cores_efficiency=_int_or_none(sysctl_values.get("hw.perflevel1.physicalcpu")),
        cpu_cores_total=_int_or_none(sysctl_values.get("hw.ncpu")),
        gpu_cores=gpu_cores,
        memory_bytes=_int_or_none(sysctl_values.get("hw.memsize")),
        firmware_version=hw.get("boot_rom_version"),
        os_version=os_version or "",
        os_build=os_build,
        sip_enabled=sip_enabled,
        secure_boot_policy=_secure_boot_policy(),
        serial_digest=serial_digest,
    )
