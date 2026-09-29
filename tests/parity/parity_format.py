# SPDX-License-Identifier: Apache-2.0
"""The one file layout the harness writes: a JSON object whose big member
(the corpus's ``cases`` list, or the answers' ``answers`` map) holds one
entry per line, so a changed case is a one-line diff."""
from __future__ import annotations

import json
from pathlib import Path


def _compact(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def write(path: Path, doc: dict, member: str) -> None:
    head = {k: v for k, v in doc.items() if k != member}
    lines = ["{"]
    for key in sorted(head):
        lines.append(f" {_compact(key)}: {_compact(head[key])},")
    body = doc[member]
    if isinstance(body, dict):
        items = [f"  {_compact(k)}: {_compact(body[k])}" for k in sorted(body)]
        open_, close = "{", "}"
    else:
        items = [f"  {_compact(v)}" for v in body]
        open_, close = "[", "]"
    lines.append(f" {_compact(member)}: {open_}")
    lines.append(",\n".join(items))
    lines.append(f" {close}")
    lines.append("}")
    text = "\n".join(lines) + "\n"
    assert json.loads(text) == json.loads(_compact(doc)), "layout must not change the value"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
