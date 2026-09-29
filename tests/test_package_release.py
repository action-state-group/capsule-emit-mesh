# SPDX-License-Identifier: Apache-2.0
"""The plugin package holds one executable and its page, never Python.

`package_release.check_no_python` runs on every staged package; these tests
hold it to refusing each way Python could ride along, and to passing the
package's real layout.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

PLUGIN_DIR = Path(__file__).resolve().parents[1] / "plugins" / "admission-policy"
sys.path.insert(0, str(PLUGIN_DIR))

import package_release  # noqa: E402


def _layout(root: Path) -> Path:
    """A staged package with every file the contract allows."""
    root.mkdir()
    for name in ("capsule-emit-mesh", "plugin.toml", "plugin-manifest.json", "README.md", "LICENSE", "NOTICE", "DEMO.md"):
        (root / name).write_text("x")
    (root / "bundle").mkdir()
    (root / "bundle" / package_release.BUNDLE_ENTRY).write_text("x")
    return root


def test_the_real_layout_carries_no_python(tmp_path):
    package_release.check_no_python(_layout(tmp_path / "capsule-emit-mesh"))


@pytest.mark.parametrize(
    "extra",
    ["door/evidence_server.py", "evidence_server.pyc", "door/requirements.lock", "requirements.txt", ".venv/x", "door/__pycache__/m.cpython-313.pyc"],
)
def test_any_python_in_the_package_is_refused(tmp_path, extra):
    root = _layout(tmp_path / "capsule-emit-mesh")
    path = root / extra
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("x")
    with pytest.raises(package_release.PackageError, match="refusing to package Python"):
        package_release.check_no_python(root)


def test_the_package_has_no_door():
    assert not (PLUGIN_DIR / "door").exists(), "the plugin carries no evidence door"
    assert "door" not in package_release.__doc__.split("Nothing else:")[0]
