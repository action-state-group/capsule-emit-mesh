#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build model-package.json from a REAL, downloaded, running mesh-llm model.

Unlike build_model_package.py (the fixture used for the mock-node demo), this
reads the actual GGUF file mesh-llm downloaded to the local Hugging Face cache
and hashes it for real. It writes NO shared/layers block: --local-model-only
serves one GGUF file directly (mesh-llm's own docs: the Skippy layer-split
package format is for distributed/mesh serving, not single-node local
serving), so a manifest claiming layer artifacts here would be a fabrication.
model_identity.py's model_package_digest() treats shared/layers as optional
for exactly this reason.

Usage:
    python3 build_real_model_package.py <path-to-gguf> <model-id> [--repo REPO] [--revision REV]
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).parent


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def build(gguf_path: Path, model_id: str, repo: str, revision: str) -> dict:
    resolved = gguf_path.resolve()
    manifest = {
        "schema_version": 1,
        "model_id": model_id,
        "source_model": {
            "path": str(resolved),
            "sha256": sha256_file(resolved),
            "repo": repo,
            "revision": revision,
            "primary_file": resolved.name,
            "canonical_ref": model_id,
            "distribution_id": model_id.split(":")[-1] if ":" in model_id else "unknown",
        },
        "format": "single-file-gguf",
        "layer_count": 0,
        "note": (
            "--local-model-only serves this GGUF directly; no Skippy layer split "
            "occurred, so shared/layers artifacts are intentionally absent "
            "rather than fabricated. See model_identity.py."
        ),
        "skippy_abi_version": None,
        "artifact_bytes": resolved.stat().st_size,
    }
    manifest_path = ROOT / "model-package" / "model-package.live.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("gguf_path", type=Path)
    parser.add_argument("model_id")
    parser.add_argument("--repo", default="bartowski/Llama-3.2-3B-Instruct-GGUF")
    parser.add_argument("--revision", default="main")
    args = parser.parse_args()

    m = build(args.gguf_path, args.model_id, args.repo, args.revision)
    out = ROOT / "model-package" / "model-package.live.json"
    print(f"wrote {out}")
    print(f"model_id={m['model_id']}")
    print(f"source_model.sha256={m['source_model']['sha256']}")
    print(f"artifact_bytes={m['artifact_bytes']}")
