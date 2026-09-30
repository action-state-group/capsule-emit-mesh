# SPDX-License-Identifier: Apache-2.0
"""What the referee parity scripts share: the fixed clock, the node names,
the test keys and the file layout.

Every node in the corpus is ``node-<letter>``. Each signs with a test key
derived from its name (:func:`private_key`), so a rebuild gives the same
corpus byte for byte and a runner can sign as the node a case puts under
test. The keys are for this corpus only. No corpus file holds a seed or a
private key: the files carry public key ids and signatures.
"""
from __future__ import annotations

import atexit
import hashlib
import json
import os
import shutil
import sys
import tempfile
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
PARITY = HERE.parent
ROOT = HERE.parents[2]
for _path in (str(ROOT), str(PARITY)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

if "model_identity" not in sys.modules:
    sys.modules["model_identity"] = types.ModuleType("model_identity")
    sys.modules["model_identity"].load_manifest = lambda p: {}
    sys.modules["model_identity"].model_package_digest = lambda m: ""

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

import parity_format  # noqa: E402

CORPUS_DIR = HERE / "corpus"
GOLDEN_DIR = HERE / "golden"
RULE_ANSWERS_DIR = HERE / "rule_answers"
INTENDED = HERE / "intended_differences.json"
MUTANTS = HERE / "mutants.json"

#: Paths judged against the Python reference, and what runs each.
PYTHON_PATHS = ("adjudicate", "service", "hold", "deliver", "classify")
#: Paths with no Python reference that follows the rules: their answers are
#: stated from the rules (``rule_answers/``).
RULE_PATHS = ("select", "request", "counts")
PATHS = PYTHON_PATHS + RULE_PATHS

#: The fixed clock every implementation runs the corpus at.
NOW = "2026-09-29T00:00:00Z"
#: When the corpus's own records were sealed.
SEALED_AT = "2026-09-28T12:00:00Z"

#: The test key of ``node-x`` is the Ed25519 key whose 32-byte seed is
#: SHA-256 of this prefix followed by the node's name.
KEY_SEED_PREFIX = "referee-parity-corpus/v1/"

_SCRATCH: Path | None = None


def private_key(node_id: str) -> Ed25519PrivateKey:
    seed = hashlib.sha256((KEY_SEED_PREFIX + node_id).encode("utf-8")).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def key_id(node_id: str) -> str:
    """The node's key id: its raw public key, hex."""
    public = private_key(node_id).public_key()
    return public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def write_key(path: Path, node_id: str) -> Path:
    """The node's test key as the PEM file the Python door loads."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        private_key(node_id).private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return path


def scratch() -> Path:
    """A throwaway directory, removed when the process ends."""
    global _SCRATCH
    if _SCRATCH is None:
        _SCRATCH = Path(tempfile.mkdtemp(prefix="referee-parity-"))
        atexit.register(shutil.rmtree, _SCRATCH, ignore_errors=True)
    return _SCRATCH


def signer(node_id: str):
    """The node's signer (``capsule_emit.signing.LocalKeypairSigner``)."""
    from capsule_emit.signing import LocalKeypairSigner

    return LocalKeypairSigner(write_key(scratch() / "keys" / f"{node_id}.pem", node_id))


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def corpus(path: str) -> dict:
    return read(CORPUS_DIR / f"{path}.json")


def expected_file(path: str) -> Path:
    """Where a path's expected answers live: the Python reference's
    (``golden/``) or the rules' (``rule_answers/``)."""
    return (GOLDEN_DIR if path in PYTHON_PATHS else RULE_ANSWERS_DIR) / f"{path}.json"


def write_cases(path: str, doc: dict) -> None:
    parity_format.write(CORPUS_DIR / f"{path}.json", doc, "cases")


def write_answers(target: Path, doc: dict) -> None:
    parity_format.write(target, doc, "answers")


def library_versions() -> dict[str, str]:
    """The released libraries the signed records were built with."""
    from importlib.metadata import version

    return {name: version(name) for name in ("agent-action-capsule", "capsule-emit", "scitt-cose")}


class Node:
    """One node under test, on a fresh ledger directory: its test key, the
    announced keys it knows (``ADMISSION_POLICY_PEER_KEYS``) and the files it
    starts with. Use as a context manager; ``state`` is what the Python door
    takes."""

    def __init__(self, node: dict) -> None:
        self.node = node

    def __enter__(self) -> "Node":
        import evidence_server as es
        from peer_keys import ENV_PEER_KEYS
        from share_policy import SharePolicy

        self._tmp = tempfile.TemporaryDirectory(prefix="referee-parity-node-")
        root = Path(self._tmp.name)
        self.key_path = write_key(root / "keys" / "node-key.pem", self.node["id"])
        self.key_id = key_id(self.node["id"])
        self.ledger_dir = root / "ledger"
        self.ledger_dir.mkdir()
        for name, lines in self.node.get("files", {}).items():
            text = "".join(json.dumps(line) + "\n" for line in lines)
            (self.ledger_dir / name).write_text(text, encoding="utf-8")
        mode = self.node.get("record_at_completion")
        self.policy = None if mode is None else SharePolicy(record_at_completion=mode)
        self.state = es.EvidenceServerState(
            ledger_dir=self.ledger_dir,
            ledger_path=self.ledger_dir / "capsules.jsonl",
            signing_key_path=self.key_path,
            share_policy=self.policy,
        )
        self._env = ENV_PEER_KEYS
        self._saved = os.environ.pop(ENV_PEER_KEYS, None)
        if self.node.get("peer_keys_env") is not None:
            os.environ[ENV_PEER_KEYS] = self.node["peer_keys_env"]
        return self

    def __exit__(self, *exc) -> None:
        os.environ.pop(self._env, None)
        if self._saved is not None:
            os.environ[self._env] = self._saved
        self._tmp.cleanup()

    def line_counts(self) -> dict[str, int]:
        return {
            p.name: len(p.read_text(encoding="utf-8").splitlines())
            for p in sorted(self.ledger_dir.iterdir())
            if p.is_file()
        }

    def appended(self, before: dict[str, int]) -> dict[str, list]:
        """Every line added to any file in the ledger directory since
        ``before``, parsed, by file name."""
        out: dict[str, list] = {}
        for p in sorted(self.ledger_dir.iterdir()):
            if not p.is_file():
                continue
            lines = p.read_text(encoding="utf-8").splitlines()[before.get(p.name, 0):]
            if lines:
                out[p.name] = [json.loads(line) for line in lines]
        return out
