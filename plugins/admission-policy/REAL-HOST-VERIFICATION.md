# Real-host verification

`tests/interop.rs` (added by `mesh-plugin-grpc-real-interop`) drives the real
`admission-policy-plugin` binary over mesh-llm's actual wire protocol, but the
*host* side of that test is a faithful stand-in — it reimplements just enough
of the host to hold up its end of the `Envelope` handshake, not the actual
`mesh-llm-host-runtime` binary. This closes that gap: everything below was run
against the real `mesh-llm serve` process.

## Why this isn't (and can't be) part of this repo's CI

`mesh-llm-host-runtime` is not published to crates.io and pulls in mesh-llm's
full native GPU/runtime toolchain (`iroh`, `skippy-runtime`, native model
serving, etc.) — the same reason `tests/interop.rs`'s header gives for not
depending on it directly. This repo's CI has no mesh-llm checkout and no way
to build that workspace. `tests/host_runtime_e2e.rs` is therefore `#[ignore]`d
by default and gated on the `MESH_LLM_HOST_BIN` env var — `cargo test` (what
CI runs) skips it cleanly; it only runs when a developer points it at a real,
separately-built `mesh-llm` binary.

## Reproducing this locally

Requires a checkout of `mesh-llm` (branch used here: `mesh-ingress-nonce-injection`,
which carries `mesh-llm-plugin`/`mesh-llm-host-runtime` at `0.76.0-rc4`; the
published `mesh-llm-plugin = "0.75.0"` this plugin depends on is verified
byte-identical in both `proto/plugin.proto` and `src/`, so there is no
wire-format drift between what this plugin builds against and what the real
host in this branch speaks).

```sh
# 1. Build the real host binary from mesh-llm's own workspace.
cd /path/to/mesh-llm
# macOS-only workaround: this workspace's .cargo/config.toml forces
# `-fuse-ld=/opt/homebrew/bin/ld64.lld`; if that isn't installed (it wasn't
# in the environment this was verified in), override it for the build:
RUSTFLAGS="" cargo build -p mesh-llm --bin mesh-llm
# -> target/debug/mesh-llm (real host + CLI, ~350MB debug binary, ~2.5 min build
#    from a warm registry cache; this workspace vendors its own
#    `mesh-llm-plugin` at 0.76.0-rc4 as a path dependency)

# 2. Build this plugin (unchanged from tests/interop.rs's build step).
cd plugins/admission-policy
cargo build --bin admission-policy-plugin

# 3. Run the real-host e2e tests.
MESH_LLM_HOST_BIN=/path/to/mesh-llm/target/debug/mesh-llm \
  cargo test --test host_runtime_e2e -- --ignored --test-threads=1

# 4. Mutant proof, same shape as tests/interop.rs's, but through the real
#    host process this time:
MESH_LLM_HOST_BIN=/path/to/mesh-llm/target/debug/mesh-llm \
  cargo test --test host_runtime_e2e --features mutant-allow-blocked \
  -- --ignored --test-threads=1
# expected: denies_blocked_model_end_to_end_through_real_host FAILS
#   (left: 200, right: 403) — the real host still dispatches the request to
#   the plugin; only the plugin's own broken decision logic changes, which is
#   exactly what this proves is being exercised.
```

Verified result (this session, 2026-08-21, macOS/aarch64, mesh-llm workspace
at commit carrying `mesh-llm-host-runtime`/`mesh-llm-plugin` `0.76.0-rc4`):

```
running 3 tests
test allows_unblocked_advertised_model_end_to_end_through_real_host ... ok
test denies_blocked_model_end_to_end_through_real_host ... ok
test malformed_body_fails_safe_at_the_real_host_before_reaching_the_plugin ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

Mutant run (`--features mutant-allow-blocked`):

```
test denies_blocked_model_end_to_end_through_real_host ... FAILED
  left: 200
 right: 403
test result: FAILED. 2 passed; 1 failed
```

## What this proves that the stand-in couldn't

1. **Real registration is actually dispatched by the real host.** The plugin
   registers via `inference::provider()`; the real host's health-probe cycle
   (`mesh-llm-host-runtime::plugin::health`) actually GETs the plugin's own
   `/v1/models`, and the real ingress
   (`network::openai::ingress::try_route_plugin_model`) actually routes a
   client's `POST /v1/chat/completions` to it by exact model name. None of
   that machinery exists in the `tests/interop.rs` stand-in, which talks
   directly to the plugin's HTTP port.
2. **A real bug the stand-in structurally could not catch.** The plugin
   declared its own endpoint address as a bare `host:port`
   (`format!("127.0.0.1:{port}")`, `src/main.rs`). The stand-in's own test
   code prepended `"http://"` itself before every request, so it never
   noticed. The real host's health-probe (`Url::parse` in
   `plugin/health.rs::endpoint_models_url`) and its actual HTTP routing path
   (`network/openai/response/external_endpoint.rs::parse_external_endpoint_url`,
   which also requires a schemed URL) both reject a bare `host:port` outright
   — the endpoint was permanently marked `unhealthy`/`unavailable` and never
   routed to at all. **Fixed** in this change: `src/main.rs` now declares
   `format!("http://127.0.0.1:{port}")`; `tests/interop.rs` updated to match
   (it no longer needs to prepend the scheme itself). This is exactly the
   class of gap this task exists to close — real end-to-end dispatch found a
   real defect the faithful-fake-host stand-in structurally could not.

## What doesn't carry over: the malformed-body case

`tests/interop.rs`'s `denies_malformed_body_fail_safe` POSTs a broken body
directly to the plugin's own HTTP port and gets a 403 with
`body_parse_failure`. Through the real host's standard
`/v1/chat/completions` ingress, this is **not reachable the same way**:

- **Syntactically invalid JSON never reaches the plugin at all.** The host's
  own ingress (`network::openai::ingress::api_proxy`) must parse the `model`
  field out of the request body *before* it can make any routing decision,
  including the plugin fallback path. When that parse fails outright, the
  host itself returns a non-200 error — verified: HTTP 503,
  `"single target None unavailable (route_to_target)"` — without ever
  connecting to the plugin. Fail-safe, but enforced by the host, not the
  plugin.
- **Valid JSON with a missing/non-string `model` field is *not* malformed
  from the host's point of view.** In this single-plugin topology (the
  plugin's advertised name is the only routable target besides the synthetic
  `mesh` model), the host's model-resolution fallback rewrites such a request
  to the sole available target before forwarding. Verified directly: the same
  body sent straight to the plugin's own port (bypassing the host) correctly
  produces `body_parse_failure`; sent through the real host, it instead
  produces `blocked_model_prefix` — proof the host rewrote/resolved the
  model field before the plugin ever saw the "malformed" version.

So `decision::malformed` (and the `mutant-allow-malformed` feature that
breaks it) is real, correctly wired, and covered — by `tests/interop.rs` and
`src/decision.rs`'s unit tests, which reach the plugin directly — but is
**architecturally unreachable through this real host's ingress** in this
topology. `tests/host_runtime_e2e.rs`'s third test verifies what the real
host actually does instead (fails safe at its own layer, never a silent 200),
and its doc comment records this finding in full so it isn't silently lost.

## Coverage summary against this task's acceptance check

| Scenario | Real host, real plugin process | Mutant proves it discriminates |
|---|---|---|
| Deny (blocked model) | ✅ `denies_blocked_model_end_to_end_through_real_host` | ✅ `mutant-allow-blocked` flips 403→200 |
| Allow (unblocked, advertised model) | ✅ `allows_unblocked_advertised_model_end_to_end_through_real_host` | n/a (positive path) |
| Malformed → fail-safe | ⚠️ host-level fail-safe verified (503, never 200); plugin's own `body_parse_failure` branch not reachable via real-host ingress — see above | ✅ `mutant-allow-malformed` still proven, but only via the direct-to-plugin `tests/interop.rs` (unaffected by this finding) |
| evidence-unavailable | n/a — this plugin has no such state (see `DELTA.md`: body access is always fully buffered by the host on the inference-provider path, so there is no reachable `BodyAccessDenied`/evidence-unavailable analog) |
