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
4. Every ALLOWED exchange is turned into a signed, hash-chained, ledgered
   Agent Action Capsule via the `capsule-emit` crate (see below) — the
   `capsule_id` is returned on the response's `admission_policy.capsule_id`.

See `PROTOCOL-NOTE.md` for why "abstain" is realized structurally (by not
advertising a model) rather than as a per-exchange decision, and why that is
a real architectural difference from the exemplar contract this plugin
replaces, not just a renaming exercise.

## Capsule production (the #1332 integration)

This plugin seals with the `capsule-emit` crate (COSE-sign -> chain ->
ledger). The mesh record kinds, split-stage records and the runtime
attestation live in `src/producer/`, written against capsule-emit's public
extension points (`seal_body`/`finish_seal` with compute-attestation
extensions, `seal_local_record`, `capsule_reference`, and a caller-defined
ledger index); `src/producer/parity_tests.rs` seals every record kind through
the older in-repo `../capsule-producer` too and requires the same bytes. The
producer is wired into two places, closing the gap the
`adv-mesh-1332-e2e-scorecard` review found — three real, independently-tested
pieces with zero lines combining any two of them:

1. **Its own `/v1/chat/completions` handler** (`src/capsule_emit.rs`): every
   admitted exchange is sealed, COSE-signed, and appended to a durable local
   ledger, with `agent_input_digest`/`agent_output_digest` computed over the
   exact request/response bytes exchanged — mutating either changes
   `capsule_id`. State (signing key + ledger + observed-lifecycle-events log)
   persists under `ADMISSION_POLICY_DATA_DIR` (default `$XDG_DATA_HOME/capsule-emit-mesh`, else
   `~/.local/share/capsule-emit-mesh`; always absolute, so a node started from another working
   directory keeps its key and chain).
2. **The #1331 lifecycle-hook broadcast** (`src/lifecycle_channel.rs`): the
   plugin declares `mesh_channel("openai.exchange.v1")` and receives the real
   host's own terminal-event envelope for the *same* exchange
   (`mesh-llm-host-runtime`'s `network/openai/ingress.rs::try_route_plugin_model`,
   which is wired into production for the raw-proxy dispatch path this
   plugin's `inference::provider()` registration uses — not just tested).
   Received envelopes are logged to `lifecycle-events.jsonl` under the data
   dir, independent of the plugin's own HTTP-handler view of the same call —
   proof the plugin observes the host's lifecycle broadcast, not just its own
   request handling.

`tests/host_runtime_e2e.rs`'s
`allowed_exchange_emits_a_signed_chained_ledgered_capsule_and_publishes_lifecycle_event`
drives a real chat-completion exchange through the real host and asserts
both wiring points, offline-verifies the resulting capsule
(`capsule_emit::verify::verify_offline`), and adversarially mutates the
signature and the observed response digest to confirm both are caught.
`real_host_ledger_cross_language_verifies_against_python_scitt_cose_reference`
re-verifies the same real-host-produced ledger against the Python
`scitt-cose`/`agent_action_capsule` reference and (optionally) the
independent `scitt-cose-go-verify` Go implementation — see that test's doc
comment for the env vars.

## Evidence page (web UI bundle)

The plugin's console page is built from `web-ui/` (`pnpm install && pnpm build`
writes `bundle/register-mesh-plugin-ui.js`), and the release workflow builds it
and packages `bundle/` plus `plugin-manifest.json` (from
`--print-package-manifest`) next to the executable; see `web-ui/README.md`.
Packaging is `package_release.py`; installing a package on a node is
[`INSTALL.md`](INSTALL.md).

The page's data comes from this plugin's own routes (`web-ui/DATA-ROUTES.md`),
read from `ADMISSION_POLICY_DATA_DIR`.

**No second process.** The other side's records are received, and requests
for yours answered, in-process: `record_push_receive` checks a pushed record
against the sender's announced key (`ADMISSION_POLICY_PEER_KEYS`) and holds
it; `evidence_answer` answers a record request under the sharing policy.
This node has no referee yet: a delivered verdict is refused, signed, and a
twin pair that differs reads "Not adjudicated: this node has no referee yet".

One more setting, optional:

- **"Asked of you"** (the peer drill's log of requests made of this node) is
  written to and read from `ADMISSION_POLICY_RECEIVED_LOG_DIR`, default
  `<ADMISSION_POLICY_DATA_DIR>/received-log`.

## Running the tests

```sh
cargo test --bin admission-policy-plugin   # decision-logic unit tests
cargo test --test interop -- --test-threads=1   # real Envelope-wire-protocol interop
```

`tests/host_runtime_e2e.rs` runs the plugin against an actual
`mesh-llm-host-runtime` process (not the stand-in host `tests/interop.rs`
implements) — see `REAL-HOST-VERIFICATION.md` for why it's `#[ignore]`d by
default, the exact reproduction steps, and a real bug this level of testing
found that the stand-in structurally could not.

### Mutant proof

Two features deliberately break one negative check each. Neither is enabled
in CI — they exist to prove the interop tests actually discriminate correct
behavior from each specific regression, over the real wire protocol:

```sh
# Fails `denies_request_for_blocked_model` (fail-open on the exact threat
# this policy exists to catch). Also fails the real-host equivalent,
# `denies_blocked_model_end_to_end_through_real_host` — see
# REAL-HOST-VERIFICATION.md.
cargo test --test interop --features mutant-allow-blocked -- --test-threads=1

# Fails `denies_malformed_body_fail_safe` (fail-open on unparseable input).
# Only reachable through the direct-to-plugin stand-in — see
# REAL-HOST-VERIFICATION.md for why the real host's own ingress can't
# exercise this branch.
cargo test --test interop --features mutant-allow-malformed -- --test-threads=1
```

See `DELTA.md` for the full already-covered-vs-needed-added accounting, and
`REAL-HOST-VERIFICATION.md` for the real-host-specific findings.

## Rebuild the package

Only packages built by `.github/workflows/release.yml` are published. The
workflow builds from the tagged commit with every action pinned to a commit,
a pinned Rust toolchain, `cargo build --locked` with the build machine's
paths remapped out of the executable, and `pnpm install --frozen-lockfile`.
The archive step (`plugins/admission-policy/package_release.py`) is
deterministic, so the same executable always gives the same archive digest.
To build the package for your own machine from a checkout of the tag:

```bash
cd plugins/admission-policy
RUSTFLAGS="--remap-path-prefix=$PWD=/build --remap-path-prefix=$HOME=/home" \
  cargo build --locked --release --bin admission-policy-plugin
(cd web-ui && pnpm install --frozen-lockfile && pnpm build)
python3 package_release.py --version "$VERSION" --target "$TARGET" \
  --binary target/release/admission-policy-plugin --out-dir dist
```

The resulting `dist/capsule-emit-mesh-$VERSION-$TARGET.tar.gz` installs with
the same command as step 3 of [`INSTALL.md`](INSTALL.md). A different compiler or build machine can produce
a different executable, and then a different digest; `SHA256SUMS` covers the
published packages.
