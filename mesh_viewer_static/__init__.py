# SPDX-License-Identifier: Apache-2.0
"""Static assets for the mesh capsule viewer (mesh_verify.js).

A real, importable package so ``importlib.resources.files`` can reach
``mesh_verify.js`` -- the inline, no-``src`` browser script the viewer HTML
embeds. Kept as data (JS) beside a package marker, exactly like
capsule-ledger's report/static and bundle_viewer/static.
"""
