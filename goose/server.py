#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""capsule-emit-goose — the action-record MCP extension for the live demo.

This is the second of the demo's two record layers. It runs as a Goose
extension (stdio MCP) and wraps two node-operations tools with
capsule-emit's ``@emitter.tool()`` decorator (Pattern A: every call Goose
makes is sealed into a verifiable Agent Action Capsule automatically — the
agent never has to know a capsule exists). This is the same mechanism as
capsule-emit's own examples/goose-capsule/server.py (po-agent), retargeted
to a node-operations narrative that pairs naturally with a mesh-llm demo.

This is the tool-call boundary. The OTHER record layer in this demo,
../capsule_sidecar.py, seals the model-serving boundary (every
/v1/chat/completions call to the real mesh-llm node). One Goose task run
against a real local mesh-llm node produces two independently verifiable,
independently chained capsule streams from the same session.

Add to ~/.config/goose/config.yaml, or pass via `goose run --with-extension`
(see ../run_live_demo.sh):

    extensions:
      capsule_emit_goose:
        enabled: true
        type: stdio
        name: capsule_emit_goose
        cmd: python3
        args: ["/path/to/poc/goose/server.py"]
        timeout: 30
        envs:
          CAPSULE_LEDGER: "/path/to/poc/ledger-live/goose-actions.jsonl"
          CAPSULE_OPERATOR: "capsule-emit-mesh-poc-demo"
          CAPSULE_DEVELOPER: "goose@v1.39.0+mesh-llm"
          CAPSULE_ANCHOR: "true"

Verify after a session:
    agent-action-capsule verify --store poc/ledger-live/goose-actions.jsonl
"""
from __future__ import annotations

import os

from mcp.server.fastmcp import FastMCP

from capsule_emit.adapters.mcp import MCPCapsuleEmitter

_OPERATOR = os.environ.get("CAPSULE_OPERATOR", "capsule-emit-mesh-poc-demo")
_DEVELOPER = os.environ.get("CAPSULE_DEVELOPER", "goose-agent@v1")
_LEDGER = os.environ.get("CAPSULE_LEDGER", "goose-actions.jsonl")
_ANCHOR = os.environ.get("CAPSULE_ANCHOR", "false").lower() not in ("0", "false", "no")

server = FastMCP(
    "capsule-emit-goose",
    instructions="Node-operations tools for a mesh-llm operator agent. Every call is sealed into a verifiable Agent Action Capsule.",
)

emitter = MCPCapsuleEmitter(
    operator=_OPERATOR,
    developer=_DEVELOPER,
    ledger=_LEDGER,
    anchor=_ANCHOR,
    model={"provider": "mesh-llm", "model_id": os.environ.get("CAPSULE_MODEL_ID", "unknown")},
)


@server.tool()
@emitter.tool(effect_type="write_capacity_request")  # consequential — gates a real allocation
def submit_capacity_request(node_id: str, gpu_hours: str, reason: str) -> dict:
    """Submit a GPU-capacity request for a mesh-llm node (consequential — sealed into a capsule)."""
    return {
        "status": "queued",
        "node_id": node_id,
        "gpu_hours": gpu_hours,
        "reason": reason,
        "request_ref": f"CAP-{node_id[-4:] if len(node_id) >= 4 else node_id}",
    }


@server.tool()
@emitter.tool(action_type="fyi")  # read-only — sealed as observation, not a gate decision
def get_node_status(node_id: str) -> dict:
    """Look up the current load/status for a mesh-llm node (read-only)."""
    statuses = {"mesh-node-demo-1": "healthy", "mesh-node-demo-2": "degraded"}
    return {"node_id": node_id, "status": statuses.get(node_id, "unknown")}


if __name__ == "__main__":
    server.run()
