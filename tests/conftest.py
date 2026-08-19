"""Test configuration: resolves mock_lifecycle_host import.

The mock lifecycle host (mock_lifecycle_host.py) ships in this repo at the
root.  This conftest adds the repo root to sys.path so test files can import
it with `from mock_lifecycle_host import ...` without qualification.

If running against a local rig worktree (mesh-1331-mock-lifecycle-host)
instead of the bundled copy, set the environment variable
MESH_RIG_DIR to the rig's path and conftest will prefer that copy.
"""
import os
import sys
from pathlib import Path

_WORKTREE_ROOT = Path(__file__).resolve().parent.parent

# Prefer an explicitly configured rig dir (local dev against separate worktree);
# fall back to the bundled copy at the repo root.
_rig_env = os.environ.get("MESH_RIG_DIR")
if _rig_env:
    _rig = Path(_rig_env)
    if not (_rig / "mock_lifecycle_host.py").exists():
        raise ImportError(
            f"MESH_RIG_DIR={_rig_env!r} is set but mock_lifecycle_host.py "
            f"was not found there."
        )
    if str(_rig) not in sys.path:
        sys.path.insert(0, str(_rig))
else:
    # Bundled copy: worktree root already has mock_lifecycle_host.py.
    if not (_WORKTREE_ROOT / "mock_lifecycle_host.py").exists():
        raise ImportError(
            f"mock_lifecycle_host.py not found at repo root {_WORKTREE_ROOT}. "
            f"Set MESH_RIG_DIR to point at the rig worktree, or ensure "
            f"mock_lifecycle_host.py is present at the repo root."
        )

if str(_WORKTREE_ROOT) not in sys.path:
    sys.path.insert(0, str(_WORKTREE_ROOT))
