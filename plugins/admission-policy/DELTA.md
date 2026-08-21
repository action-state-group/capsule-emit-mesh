# Delta: what mesh-llm's real plugin system already covers vs. what's missing

Written against `mesh-llm-plugin`/`mesh-llm-host-runtime` as of the
`mesh-ingress-nonce-injection` branch of `github.com/Mesh-LLM/mesh-llm`
(crates.io `mesh-llm-plugin = 0.75.0`). See `PROTOCOL-NOTE.md` for the
narrative version of this same finding.

## Already covered — used as-is in this plugin, nothing invented

- **Handshake and lifecycle.** `Initialize`/`Health`/`Shutdown`
  request-response framing, protocol version negotiation, and capability
  declaration are real and complete. No changes needed.
- **Wire transport.** Length-prefixed protobuf `Envelope` over a Unix domain
  socket (or named pipe), with the plugin as the connecting client — real,
  used as-is. (Not gRPC — see `PROTOCOL-NOTE.md`.)
- **A working dispatch path for OpenAI-compatible traffic.**
  `inference::provider()` + the host's own `/v1/models` health-probe cycle is
  a real, functioning mechanism for a plugin to receive real HTTP requests for
  models it declares. This plugin uses it unmodified.
- **Body delivery on that path.** Always fully buffered by the host before
  routing — no plugin-side opt-in needed, and correspondingly no
  "body withheld" state to handle.
- **`HttpBodyMode` (`BUFFERED`/`STREAMED`).** A real, host-enforced enum — but
  scoped to `HttpBindingManifest` custom routes, not the inference-provider
  path. Confirmed real and correctly scoped, not used by this plugin because
  its admission surface doesn't need a custom route.

## Needed adding — genuine gaps, not documentation gaps

- **No arbitrary pre-dispatch observation hook.** Nothing in the real
  protocol lets a plugin observe or gate an exchange regardless of which
  backend serves it. `MeshEvent.Kind` is topology-only
  (`PEER_UP`/`PEER_DOWN`/`PEER_UPDATED`/`LOCAL_ACCEPTING`/`LOCAL_STANDBY`/
  `MESH_ID_UPDATED`). This is the exemplar contract's core assumption, and it
  has no real analog. Filing this as "please specify phase names" would be
  wrong — the phases don't exist as a concept.
- **No wildcard/pattern model registration.** A policy that must react to a
  previously-unknown blocked name at request time (rather than a static,
  pre-advertised list) has no interop path today. Every governed name must be
  known in advance and (re-)advertised through `/v1/models` for enforcement
  to take effect, subject to the host's health-probe interval
  (`ENDPOINT_STARTUP_GRACE_SECS` / `HEALTH_CHECK_INTERVAL_SECS` in
  `mesh-llm-host-runtime::plugin::health`) — so there is also a real
  propagation delay between declaring a new blocked name and the host
  honoring it.
- **No header sanitization for plugin-served HTTP endpoints.** The exemplar
  contract's `sanitized_headers` concept (Authorization/Cookie stripped
  before the plugin sees them) has no real analog. Headers reach a
  provider-registered plugin's HTTP endpoint unfiltered
  (`external_endpoint::rewrite_http_request_target` only rewrites
  host/port/path). Anyone treating a third-party plugin as an untrusted
  boundary needs to know this holds today, independent of anything this PR
  changes.

## What this plugin demonstrates instead of assumes

Because "abstain" has no real per-call representation, this plugin realizes
it structurally: it advertises only the model names it actively governs
(`ADMISSION_POLICY_BLOCKED_MODELS`), so the host's normal routing continues
untouched for every other model — the plugin is never even asked about them.
Enforcement is "deny every request routed to a name I chose to own," not
"decide allow/deny for every request in the mesh."
