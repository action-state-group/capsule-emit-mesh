# DRAFT — for mesh-llm#1331, not yet sent

This is a draft technical note, written for the reference implementation in
this directory. It has not been posted anywhere. Sending it (and choosing any
attribution) is an operator decision, made separately from writing the code.

---

## What the private spike got right, and what it got wrong

A prior private spike found that `capsule-emit-mesh`'s own exemplar contract
(`exemplar/plugin_contract.py`, `mesh-llm#1331`) defines the plugin interface
as in-process Python with no serialization format or process boundary, and
concluded mesh-llm has **no cross-process plugin wire protocol at all**. That
premise is wrong. mesh-llm ships one, has for a while, and it works: the
published `mesh-llm-plugin` crate (crates.io), `proto/plugin.proto`, a DSL for
declaring plugin manifests, and a host runtime that loads external plugin
processes and speaks it. The reference plugin in this directory
(`admission-policy-plugin`) builds against that real protocol and runs green
through `Initialize → Health → Shutdown` plus real HTTP dispatch — see this
PR's tests.

One correction to the wire format itself: it is **not gRPC**. `mesh-llm-plugin`
depends on `prost`/`prost-build`, not `tonic` — there is no HTTP/2 framing or
gRPC service definition anywhere in the crate. The actual mechanism is a
length-prefixed protobuf `Envelope` message, framed over a Unix domain socket
(or a named pipe on Windows), with the host spawning the plugin as a
subprocess and passing the socket path via `MESH_LLM_PLUGIN_ENDPOINT`. Framing
it as "gRPC-native" overstates what's there; "Envelope-over-local-socket" is
accurate.

## The bigger correction: there is no per-exchange lifecycle hook

The exemplar contract's `Manifest.phases` field assumes a plugin can ask to be
called at named lifecycle points — `request_received`, `backend_selected`,
`exchange_finished` — for **every** OpenAI-compatible exchange, regardless of
which backend ultimately serves it. That shape does not exist in the real
protocol. `MeshEvent.Kind` — the only event enum in `plugin.proto` — is
mesh-topology-only: `PEER_UP`, `PEER_DOWN`, `PEER_UPDATED`, `LOCAL_ACCEPTING`,
`LOCAL_STANDBY`, `MESH_ID_UPDATED`. Nothing in either direction of the wire
protocol carries a per-request lifecycle event to a plugin that isn't itself
handling that request.

The real, working mechanism for a plugin to be dispatched OpenAI-compatible
traffic is registering as an **inference provider**
(`inference: [provider(id, address)]` in the DSL, which sets
`managed_by_plugin = true` on the endpoint manifest). But dispatch to it is:

- **Exact-name-scoped.** The host matches the requested `model` string exactly
  against each endpoint's served-models list (itself discovered by the host
  actively probing the plugin's own `/v1/models` — see
  `mesh-llm-host-runtime::plugin::health::probe_endpoint`). There is no
  wildcard or pattern field anywhere in `EndpointManifest`.
- **Last-resort-only.** A plugin endpoint is only consulted when no local or
  remote backend already serves that exact model name
  (`network::openai::ingress::route_missing_local_model`).

So an admission-policy plugin built on the real protocol enforces policy by
being the registered provider for every blocked model name it knows about in
advance, advertised through its own `/v1/models`. "Abstain" is realized
structurally — by simply not advertising a model — rather than as a per-call
decision a plugin returns. This is a materially different shape from the
exemplar's phase-based model, not a renaming exercise, and the reference
plugin in this directory is built that way deliberately (see its
`blocked_models()` doc comment).

## `HttpBodyMode` does answer the body-access question — narrowly

`HttpBindingManifest.request_body_mode`/`response_body_mode`
(`HttpBodyMode::BUFFERED`/`STREAMED`) is real, and the host genuinely honors
it (`mesh-llm-host-runtime::api::routes::plugins::binding_transfer_mode`). But
it applies only to a plugin's **own custom HTTP routes**, declared via
`http_binding()`/`dsl::http::*` and relayed to the plugin process over the
Envelope RPC bridge — not to the inference-provider path this plugin uses.
The OpenAI-dispatch path is always fully buffered by the host before any
routing decision is made (the request is materialized into a
`BufferedHttpRequest` up front). So the spike's `BodyAccessDenied` /
evidence-unavailable state — the host granting or withholding body access —
has no reachable analog on the provider path: the host always hands the
plugin a complete body. `HttpBodyMode` is the real mechanism for the question
it was designed to answer; it just answers a different question than the one
an admission-policy plugin on the inference-provider path needs answered.

## Suggested #1331 addendum

- Retitle the request from "no wire protocol is specified" to "the
  contract's phase-based model has no analog in the real protocol." The
  cross-process handshake itself is not the gap; the per-exchange
  observation hook is.
- If a future "observe every exchange regardless of destination backend"
  capability is wanted, treat it as new surface to design, not a
  documentation gap in the existing kit.
- Document the provider/exact-model-registration pattern as the sanctioned
  approach for admission-policy-shaped plugins specifically — nothing in the
  current plugin docs frames `inference::provider()` as a policy mechanism,
  only as "serve this model yourself."
- A working reference implementation is `capsule-emit-mesh/plugins/admission-policy/`
  in this PR.
