#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Stage and archive one platform's capsule-emit-mesh plugin package.

Used by .github/workflows/release.yml for every build target, and runnable
locally for a dry run of the same package:

    cargo build --locked --release --bin admission-policy-plugin
    (cd web-ui && pnpm install --frozen-lockfile && pnpm build)
    python3 package_release.py --version 0.2.0 \
        --target aarch64-apple-darwin \
        --binary target/release/admission-policy-plugin --out-dir dist

The archive follows mesh-llm's plugin package contract (docs/plugins/README.md
in Mesh-LLM/mesh-llm, checked against mesh-llm-plugin-manager's extractor):

    capsule-emit-mesh-<version>-<target>.tar.gz
      capsule-emit-mesh/
        capsule-emit-mesh          the executable, renamed to the plugin name
        plugin.toml
        plugin-manifest.json       printed by the binary (--print-package-manifest)
        bundle/register-mesh-plugin-ui.js
        README.md                  INSTALL.md from this directory
        DEMO.md                    the five-minute demo (required: INSTALL.md links it)
        LICENSE, NOTICE

Nothing else: no Python, no second process to install or run. The package
refuses to build with any Python in it (`check_no_python`).

Unix targets ship .tar.gz only: mesh-llm's .zip extractor does not restore
the executable bit, so a .zip would install a plugin the host cannot start.

The archive is byte-for-byte deterministic for a given set of input files
(sorted entries, fixed owner and mode, mtime from SOURCE_DATE_EPOCH or 0, gzip
header mtime 0), so a rebuild from the tagged commit that produces the same
executable produces the same archive digest.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path

PLUGIN_NAME = "capsule-emit-mesh"
BUNDLE_ENTRY = "register-mesh-plugin-ui.js"
UNIX_TARGETS = (
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
)
PLUGIN_DIR = Path(__file__).resolve().parent
REPO_ROOT = PLUGIN_DIR.parent.parent
VERSION_LINE = re.compile(r'^version\s*=\s*"([^"]+)"\s*$', re.MULTILINE)
SEMVER = re.compile(r"^(\d+\.\d+\.\d+)(-[0-9A-Za-z.-]+)?$")


class PackageError(Exception):
    """A package input is missing or does not match what the host expects."""


@dataclass(frozen=True)
class Package:
    archive: Path
    sha256: str


def core_version(version: str) -> str:
    """`0.2.0-rc.1` -> `0.2.0`; rejects anything that is not semver."""
    match = SEMVER.match(version)
    if match is None:
        raise PackageError(f"version {version!r} is not MAJOR.MINOR.PATCH[-PRERELEASE]")
    return match.group(1)


def check_plugin_toml_version(version: str) -> None:
    text = (PLUGIN_DIR / "plugin.toml").read_text(encoding="utf-8")
    match = VERSION_LINE.search(text)
    if match is None:
        raise PackageError("plugin.toml has no version line")
    declared = match.group(1)
    if declared != core_version(version):
        raise PackageError(
            f"plugin.toml declares version {declared}, but the release version is "
            f"{version}; bump plugin.toml before tagging"
        )


def print_manifest(binary: Path) -> bytes:
    try:
        result = subprocess.run(
            [str(binary), "--print-package-manifest"],
            check=True,
            capture_output=True,
        )
        printed = json.loads(result.stdout)
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError) as error:
        raise PackageError(
            f"{binary} --print-package-manifest failed: {error}"
        ) from error
    reviewed = json.loads(
        (PLUGIN_DIR / "plugin.package.json").read_text(encoding="utf-8")
    )
    if printed != reviewed:
        raise PackageError(
            "the binary's --print-package-manifest output differs from plugin.package.json"
        )
    return result.stdout


def check_bundle(bundle: Path) -> None:
    if not bundle.is_dir():
        raise PackageError(f"{bundle} is missing; run `pnpm build` in web-ui/ first")
    entries = sorted(p.name for p in bundle.iterdir())
    if entries != [BUNDLE_ENTRY]:
        raise PackageError(f"bundle/ must hold exactly {BUNDLE_ENTRY}, found {entries}")


def check_no_python(root: Path) -> None:
    """The plugin is one executable and its page: refuse any Python file, a
    requirements file or a virtualenv anywhere in the staged package."""
    found = sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.suffix in {".py", ".pyc", ".pyi"}
        or path.name.startswith("requirements")
        or path.name in {".venv", "__pycache__"}
    )
    if found:
        raise PackageError(f"refusing to package Python: {found}")


def stage(root: Path, binary: Path, manifest: bytes) -> None:
    root.mkdir(parents=True)
    shutil.copyfile(binary, root / PLUGIN_NAME)
    shutil.copyfile(PLUGIN_DIR / "plugin.toml", root / "plugin.toml")
    (root / "plugin-manifest.json").write_bytes(manifest)
    shutil.copytree(PLUGIN_DIR / "bundle", root / "bundle")
    shutil.copyfile(PLUGIN_DIR / "INSTALL.md", root / "README.md")
    shutil.copyfile(REPO_ROOT / "LICENSE", root / "LICENSE")
    shutil.copyfile(REPO_ROOT / "NOTICE", root / "NOTICE")
    if not (PLUGIN_DIR / "DEMO.md").is_file():
        raise PackageError("DEMO.md is missing; INSTALL.md links it, so it must ship")
    shutil.copyfile(PLUGIN_DIR / "DEMO.md", root / "DEMO.md")

    # Fail closed on anything beyond the contract's files: never keys,
    # ledgers, or demo data.
    allowed = {
        PLUGIN_NAME,
        "plugin.toml",
        "plugin-manifest.json",
        "bundle",
        "README.md",
        "LICENSE",
        "NOTICE",
        "DEMO.md",
    }
    unexpected = sorted(p.name for p in root.iterdir() if p.name not in allowed)
    if unexpected:
        raise PackageError(f"refusing to package unexpected files: {unexpected}")
    check_no_python(root)


def write_archive(staging: Path, archive: Path, mtime: int) -> None:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for path in sorted(staging.rglob("*")):
            rel = path.relative_to(staging).as_posix()
            info = tar.gettarinfo(str(path), arcname=rel)
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mtime = mtime
            executable = path.is_dir() or rel == f"{PLUGIN_NAME}/{PLUGIN_NAME}"
            info.mode = 0o755 if executable else 0o644
            if path.is_file():
                with path.open("rb") as handle:
                    tar.addfile(info, handle)
            else:
                tar.addfile(info)
    with (
        archive.open("wb") as raw,
        gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as gz,
    ):
        gz.write(buffer.getvalue())


def build_package(
    version: str,
    target: str,
    binary: Path,
    out_dir: Path,
) -> Package:
    if target not in UNIX_TARGETS:
        raise PackageError(
            f"unsupported target {target}; expected one of {UNIX_TARGETS}"
        )
    check_plugin_toml_version(version)
    check_bundle(PLUGIN_DIR / "bundle")
    manifest = print_manifest(binary)

    out_dir.mkdir(parents=True, exist_ok=True)
    archive = out_dir / f"{PLUGIN_NAME}-{version}-{target}.tar.gz"
    mtime = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
    with tempfile.TemporaryDirectory() as tmp:
        staging = Path(tmp)
        stage(staging / PLUGIN_NAME, binary, manifest)
        write_archive(staging, archive, mtime)

    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    # sha256sum's format, so `sha256sum -c` / `shasum -a 256 -c` read it.
    Path(f"{archive}.sha256").write_text(
        f"{digest}  {archive.name}\n", encoding="utf-8"
    )
    return Package(archive=archive, sha256=digest)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--version", required=True, help="release version, no leading v"
    )
    parser.add_argument("--target", required=True, help="Rust target triple")
    parser.add_argument(
        "--binary", required=True, type=Path, help="built plugin executable"
    )
    parser.add_argument("--out-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        package = build_package(
            args.version,
            args.target,
            args.binary,
            args.out_dir,
        )
    except PackageError as error:
        print(f"package_release: {error}", file=sys.stderr)
        return 1
    print(f"{package.sha256}  {package.archive.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
