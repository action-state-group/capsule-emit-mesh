# SPDX-License-Identifier: Apache-2.0
"""Test configuration: resolve mock_lifecycle_host AND guard import order.

(1) mock_lifecycle_host.py ships at the repo root; add the root to sys.path so
    tests can `from mock_lifecycle_host import ...`. If running against a
    separate rig worktree, set MESH_RIG_DIR to prefer that copy.
(2) test_forwarded_copy_and_keys.py stubs agent_action_capsule.contracts at
    collection time; import the real stack + mesh_record_emitter/verifier HERE
    first so their EffectRecord/Disposition bindings resolve to the real
    classes before any later setattr.
"""
import os
import sys
from pathlib import Path

_WORKTREE_ROOT = Path(__file__).resolve().parent.parent

# (1) mock_lifecycle_host resolution
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
elif not (_WORKTREE_ROOT / "mock_lifecycle_host.py").exists():
    raise ImportError(
        f"mock_lifecycle_host.py not found at repo root {_WORKTREE_ROOT}. "
        f"Set MESH_RIG_DIR to point at the rig worktree, or ensure "
        f"mock_lifecycle_host.py is present at the repo root."
    )

if str(_WORKTREE_ROOT) not in sys.path:
    sys.path.insert(0, str(_WORKTREE_ROOT))

# (2) import-order guard — bind real agent_action_capsule classes before collection
import agent_action_capsule  # noqa: E402,F401
import agent_action_capsule.canonical  # noqa: E402,F401
import agent_action_capsule.contracts  # noqa: E402,F401
import agent_action_capsule.emit  # noqa: E402,F401
import agent_action_capsule.verify  # noqa: E402,F401
import mesh_record_emitter  # noqa: E402,F401
import mesh_record_verifier  # noqa: E402,F401
