# SPDX-License-Identifier: Apache-2.0
"""Test configuration: resolve mock_lifecycle_host AND guard import order.

(1) mock_lifecycle_host.py ships at the repo root; add the root to sys.path so
    tests can `from mock_lifecycle_host import ...`. If running against a
    separate rig worktree, set MESH_RIG_DIR to prefer that copy.
(2) test_forwarded_copy_and_keys.py and test_bilateral_demo.py both stub
    agent_action_capsule.contracts AND scitt_cose at collection time (a bare
    types.ModuleType with no `cll` submodule); import the real stack +
    mesh_record_emitter/verifier + mesh_coordinator_receipt_emitter +
    scitt_cose.cll HERE first so their real
    classes/submodules resolve before any later setdefault() no-ops on top
    of them. Without this, test_checkpointing.py's `from scitt_cose import
    cll` fails whenever a stubbing test file collects first (alphabetical
    order is not a safe assumption to rely on instead).

    NOTE: this deliberately does NOT extend to `model_identity` -- unlike
    `agent_action_capsule`/`scitt_cose` (safe to bind for real, since
    downstream tests only need their real classes to exist), several
    stubbing test files' OWN tests (test_forwarded_copy_and_keys.py,
    test_bilateral_demo.py, test_replay_spot_check.py) actively DEPEND on
    `model_identity.load_manifest` staying a no-op stub (they construct a
    `NodeState`/similar against a `manifest_path` that is never written).
    Binding the real module here would make those tests fail deterministically
    instead of passing by accident -- worse, not better. Any test file that
    imports `capsule_sidecar` for real and could collect before those three
    (alphabetically or otherwise) must carry the SAME "stub `model_identity`
    if absent" guard itself -- see test_ask_history.py's top matter for the
    reused idiom.
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
import mesh_coordinator_receipt_emitter  # noqa: E402,F401
import scitt_cose  # noqa: E402,F401
import scitt_cose.cll  # noqa: E402,F401
