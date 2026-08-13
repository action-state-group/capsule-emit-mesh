#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build a small, REAL (not fabricated) model-package.json fixture for the PoC.

This does not vendor real GGUF model weights (out of scope for a proof-of-
concept, and far too large for this scratch tree). Instead it writes small
placeholder artifact files with genuine, fixed content and hashes them for
real with sha256 -- so every digest in model-package.json is an authentic
digest of bytes that exist on disk, not a fabricated hex string.

Shape follows mesh-llm's own manifest spec exactly:
  https://github.com/Mesh-LLM/mesh-llm/blob/main/website/src/docs/pages/model-package-spec.md
(schema_version 1: source_model, shared.{metadata,embeddings,output}, layers[]).

In a real deployment, the sidecar reads mesh-llm's OWN downloaded
model-package.json for the model currently loaded, instead of this fixture.
See poc/README.md "Honest limitations" for why a fixture is used here.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).parent
PKG_DIR = ROOT / "model-package"
MODEL_ID = "capsule-emit-poc/tiny-fixture-model:Q4_K_XL"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_artifact(rel_path: str, content: bytes) -> dict:
    path = PKG_DIR / rel_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return {
        "path": rel_path,
        "artifact_bytes": len(content),
        "sha256": sha256_file(path),
    }


def build() -> dict:
    source_model_bytes = (
        b"CAPSULE-EMIT-MESH-POC FIXTURE SOURCE MODEL (not a real GGUF).\n"
        b"This file stands in for a downloaded source model artifact so that\n"
        b"model_package_digest below is a real sha256 of real bytes.\n"
    )
    source_path = PKG_DIR / "source" / "tiny-fixture-model.gguf"
    source_path.parent.mkdir(parents=True, exist_ok=True)
    source_path.write_bytes(source_model_bytes)

    metadata = write_artifact("shared/metadata.gguf", b"fixture-metadata-tensor-block\n")
    embeddings = write_artifact("shared/embeddings.gguf", b"fixture-embeddings-tensor-block\n")
    output = write_artifact("shared/output.gguf", b"fixture-output-tensor-block\n")
    layer0 = write_artifact("layers/layer-00000.gguf", b"fixture-layer-0-tensor-block\n")
    layer1 = write_artifact("layers/layer-00001.gguf", b"fixture-layer-1-tensor-block\n")

    manifest = {
        "schema_version": 1,
        "model_id": MODEL_ID,
        "source_model": {
            "path": str(source_path.relative_to(PKG_DIR)),
            "sha256": sha256_file(source_path),
            "repo": "capsule-emit-poc/tiny-fixture-model",
            "revision": "fixture-0001",
            "primary_file": "tiny-fixture-model.gguf",
            "canonical_ref": MODEL_ID,
            "distribution_id": "Q4_K_XL",
        },
        "format": "layer-package",
        "layer_count": 2,
        "activation_width": 64,
        "shared": {
            "metadata": {**metadata, "tensor_count": 0, "tensor_bytes": 0},
            "embeddings": {**embeddings, "tensor_count": 1, "tensor_bytes": len(b"fixture-embeddings-tensor-block\n")},
            "output": {**output, "tensor_count": 1, "tensor_bytes": len(b"fixture-output-tensor-block\n")},
        },
        "layers": [
            {"layer_index": 0, "tensor_count": 4, "tensor_bytes": len(b"fixture-layer-0-tensor-block\n"), **layer0},
            {"layer_index": 1, "tensor_count": 4, "tensor_bytes": len(b"fixture-layer-1-tensor-block\n"), **layer1},
        ],
        "skippy_abi_version": "1.2.3-poc",
        "created_at_unix_secs": 1791600000,
    }

    manifest_path = PKG_DIR / "model-package.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


if __name__ == "__main__":
    m = build()
    print(f"wrote {PKG_DIR / 'model-package.json'}")
    print(f"model_id={m['model_id']}")
