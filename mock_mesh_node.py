#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""A minimal, schema-accurate stand-in for a local mesh-llm node's /v1 API.

WHY THIS EXISTS (read poc/README.md "Honest limitations" for the full story):
this sandbox's tool policy blocks executing a downloaded third-party release
binary (the mesh-llm prebuilt darwin-arm64 binary was fetched for read-only
inspection but running it was denied by the harness's permission classifier
as "executing code from an external, untrusted source"). That leaves no way
to run a real mesh-llm node inside this session. To still exercise the
sidecar end-to-end, this file reimplements just enough of mesh-llm's own
OpenAI-compatible surface -- copied field-for-field from the real source in
this same scratch clone -- to be a faithful stand-in:

  - crates/openai-frontend/src/chat.rs      ChatCompletionRequest/Response,
                                             ChatMessage, AssistantMessage,
                                             ChatCompletionChoice, Usage
  - crates/openai-frontend/src/errors.rs    ErrorResponse / ErrorBody shape

This is NOT a mesh-llm plugin and ships no mesh-llm code. It is a test
fixture so the sidecar (poc/capsule_sidecar.py) can be demonstrated against
a real HTTP server speaking the real wire shape, pending someone re-running
this same sidecar against an actual `mesh-llm serve --local-model-only` node
(instructions in README).
"""
from __future__ import annotations

import json
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODEL_ID = "capsule-emit-poc/tiny-fixture-model:Q4_K_XL"
REFUSAL_TRIGGER = "TRIGGER_GUARDRAIL_REFUSAL"


def chat_completion_response(request: dict) -> dict:
    messages = request.get("messages", [])
    last_user = next((m for m in reversed(messages) if m.get("role") == "user"), {})
    prompt_text = last_user.get("content", "")
    if isinstance(prompt_text, list):
        prompt_text = " ".join(p.get("text", "") for p in prompt_text if isinstance(p, dict))

    reply = f"[fixture reply to: {prompt_text[:60]!r}]"
    prompt_tokens = max(1, len(prompt_text.split()))
    completion_tokens = max(1, len(reply.split()))

    return {
        "id": f"chatcmpl-{uuid.uuid4()}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": request.get("model", MODEL_ID),
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": reply},
                "logprobs": None,
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
        },
    }


def chat_completion_sse_frames(request: dict) -> list[bytes]:
    """Return SSE-framed chunks for the same content as chat_completion_response.

    Produces the streaming (text/event-stream) equivalent of the non-streaming
    response.  Usage data is deliberately NOT included in stream chunks: real
    mesh-llm sends usage only in a trailing annotation after [DONE] (an
    implementation detail that varies by version), and the sidecar's
    reassemble_streamed_response does not pull usage into the reassembled object.
    Excluding usage here keeps the digest domain identical to the non-streaming path
    and avoids a number-rule dependency in test transcripts.

    Frame structure (matches synthesize_sse in capsule_sidecar.py):
      1. Role delta: {"delta": {"role": "assistant"}}
      2. Content delta(s): {"delta": {"content": "..."}}
      3. Finish delta: {"delta": {}, "finish_reason": "stop"}
      4. [DONE] sentinel
    """
    full = chat_completion_response(request)
    message = (full.get("choices") or [{}])[0].get("message", {})

    base = {
        "id": full["id"],
        "object": "chat.completion.chunk",
        "created": full["created"],
        "model": full["model"],
    }

    def _frame(delta: dict, finish_reason: str | None = None) -> bytes:
        chunk = {**base, "choices": [{"index": 0, "delta": delta, "finish_reason": finish_reason}]}
        return f"data: {json.dumps(chunk)}\n\n".encode("utf-8")

    frames = [_frame({"role": "assistant"})]
    content = message.get("content") or ""
    if content:
        frames.append(_frame({"content": content}))
    frames.append(_frame({}, finish_reason="stop"))
    frames.append(b"data: [DONE]\n\n")
    return frames


def guardrail_refusal_error() -> tuple[int, dict]:
    # Shape matches errors.rs ErrorResponse { error: ErrorBody }.
    # Mirrors a pre-dispatch guardrails rejection (crates/openai-frontend/src/guardrails/):
    # the request never reached generation.
    body = {
        "error": {
            "message": "request rejected by guardrails policy before dispatch (PoC fixture trigger)",
            "type": "invalid_request_error",
            "param": "messages",
            "code": "guardrail_policy_rejected",
        }
    }
    return 400, body


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # noqa: A003 - quiet default logging
        pass

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "mesh-llm-poc-fixture/0.75.1-stand-in")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        if self.path == "/v1/models":
            self._send_json(200, {"object": "list", "data": [{"id": MODEL_ID, "object": "model"}]})
        else:
            self._send_json(404, {"error": {"message": "not found", "type": "not_found_error", "param": None, "code": None}})

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b""
        if self.path != "/v1/chat/completions":
            self._send_json(404, {"error": {"message": "not found", "type": "not_found_error", "param": None, "code": None}})
            return
        try:
            request = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            self._send_json(400, {"error": {"message": "invalid JSON", "type": "invalid_request_error", "param": None, "code": None}})
            return

        text_blob = json.dumps(request)
        if REFUSAL_TRIGGER in text_blob:
            status, body = guardrail_refusal_error()
            self._send_json(status, body)
            return

        if request.get("stream"):
            frames = chat_completion_sse_frames(request)
            body = b"".join(frames)
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Server", "mesh-llm-poc-fixture/0.75.1-stand-in")
            self.end_headers()
            self.wfile.write(body)
        else:
            self._send_json(200, chat_completion_response(request))


def run(host: str = "127.0.0.1", port: int = 9337) -> None:
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"mock mesh-llm node fixture listening on http://{host}:{port} (model={MODEL_ID})")
    server.serve_forever()


if __name__ == "__main__":
    import sys

    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9337
    run(port=port)
