# SPDX-License-Identifier: Apache-2.0
"""model_package_digest, computed exactly as issue #1233 proposes:

    model_package_digest =
      sha256(canonical_manifest + artifact_digests + runtime_abi)

We instantiate this concretely (the issue leaves the exact framing open) as
the JSON-DIGEST (RFC 8785 JCS + SHA-256, agent_action_capsule.canonical) over
a canonical object containing:
  - model_id / canonical_ref (package identity)
  - source_model.sha256 (source artifact digest)
  - every shared.*.sha256 and layers[].sha256, in manifest order
  - skippy_abi_version (the runtime ABI compatibility declaration)

This reads mesh-llm's OWN model-package.json shape (schema_version 1) --
see poc/README.md for why this PoC reads a local fixture manifest rather than
a real downloaded package (no model was actually served in this sandbox).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agent_action_capsule.canonical import json_digest


def load_manifest(manifest_path: Path) -> dict[str, Any]:
    return json.loads(manifest_path.read_text())


def model_package_digest(manifest: dict[str, Any]) -> str:
    artifact_digests = [manifest["source_model"]["sha256"]]
    for key in ("metadata", "embeddings", "output"):
        block = manifest.get("shared", {}).get(key)
        if block:
            artifact_digests.append(block["sha256"])
    for layer in sorted(manifest.get("layers", []), key=lambda item: item["layer_index"]):
        artifact_digests.append(layer["sha256"])
    for projector in manifest.get("projectors", []):
        artifact_digests.append(projector["sha256"])

    canonical_identity = {
        "model_id": manifest["model_id"],
        "canonical_ref": manifest["source_model"].get("canonical_ref", manifest["model_id"]),
        "source_model_sha256": manifest["source_model"]["sha256"],
        "artifact_digests": artifact_digests,
        "runtime_abi": manifest.get("skippy_abi_version"),
    }
    return json_digest(canonical_identity)
