# admission-policy-plugin

A real `mesh-llm-plugin` gRPC-ecosystem plugin that denies OpenAI-compatible
exchanges whose `model` matches a blocked prefix, built against mesh-llm's
actual published plugin protocol — not an invented one.

This supersedes the private spike (`mesh-private-plugin-spike`, not part of
this repo) that reimplemented the same admission logic over a hand-invented
stdio/JSON protocol, on the mistaken premise that mesh-llm has no
cross-process plugin wire format. It does: `mesh-llm-plugin` (published on
crates.io) ships `proto/plugin.proto`, a length-prefixed protobuf `Envelope`
wire format over a Unix domain socket / named pipe, and a DSL for declaring
plugin manifests. This crate depends on it directly.

## What this is not

The wire protocol is **not** gRPC/HTTP2 — `mesh-llm-plugin`'s `Cargo.toml`
depends on `prost`/`prost-build` only, no `tonic`. It is a custom
length-prefixed protobuf framing over a local socket. Any framing that calls
this "gRPC-native" is imprecise; see `PROTOCOL-NOTE.md`.

## How it works

1. On startup, binds its own small HTTP server (`axum`) to an ephemeral local
   port and declares that address as an `inference` provider endpoint
   (`managed_by_plugin = true`, protocol `openai_compatible`) in its manifest,
   via `mesh-llm-plugin`'s `inference::provider()` DSL builder.
2. Speaks the real `Envelope`-over-socket handshake
   (`InitializeRequest`/`Response`, `HealthRequest`/`Response`,
   `ShutdownRequest`/`Response`) via `mesh_llm_plugin::PluginRuntime::run`.
3. Advertises exactly the blocked model name(s) it enforces
   (`ADMISSION_POLICY_BLOCKED_MODELS`, comma-separated; defaults to
   `blocked-test-model`) via its own `/v1/models`, and denies
   `/v1/chat/completions` requests for them with an HTTP 403 and a
   deny-reason body. Malformed/unparseable request bodies are also denied
   (fail-safe), never silently allowed.

See `PROTOCOL-NOTE.md` for why "abstain" is realized structurally (by not
advertising a model) rather than as a per-exchange decision, and why that is
a real architectural difference from the exemplar contract this plugin
replaces, not just a renaming exercise.

## Running the tests

```sh
cargo test --bin admission-policy-plugin   # decision-logic unit tests
cargo test --test interop -- --test-threads=1   # real Envelope-wire-protocol interop
```

### Mutant proof

Two features deliberately break one negative check each. Neither is enabled
in CI — they exist to prove the interop test actually discriminates correct
behavior from each specific regression, over the real wire protocol:

```sh
# Fails `denies_request_for_blocked_model` (fail-open on the exact threat
# this policy exists to catch):
cargo test --test interop --features mutant-allow-blocked -- --test-threads=1

# Fails `denies_malformed_body_fail_safe` (fail-open on unparseable input):
cargo test --test interop --features mutant-allow-malformed -- --test-threads=1
```

See `DELTA.md` for the full already-covered-vs-needed-added accounting.
