# Evidence page data routes

The Evidence page is a mesh-llm plugin page. The console's plugin web UI
contract lets a page reach its own plugin's routes, and only those, through
`host.network.fetchPlugin(path)`. The console serves a plugin's declared
HTTP bindings at `/api/plugins/capsule-emit-mesh/http/<path>` and its tools at
`/api/plugins/capsule-emit-mesh/tools/<name>`, so the page asks for
`http/<path>` and `tools/<name>`. It reads **plugin-owned routes only**, and
no host route beyond the two console reads below.

Plugin HTTP routes (`mesh_llm_plugin::http::get`) answer JSON, so files the
plugin keeps on disk arrive wrapped in JSON.

| Plugin route, under `http/` (GET unless noted) | Answers | Read from (under the plugin's data dir) |
| --- | --- | --- |
| `door` | `{ "state": "ready" \| "not_running" \| "auth_failed" \| "unknown", "url": "<door address>" }`: whether this node's evidence door runs and holds this install's token; the page warns when it does not | the door itself (`GET /health`, authenticated) |
| `ledger` | `{ "records": [<capsule>...], "node_pub_key_pem": "<PEM>" \| null }`; padding records are never listed; an empty list while nothing is sealed | `ledger/capsules.jsonl` + `ledger/node-key.pub.pem` |
| `ledger/signed-statement?capsule_id=<id>` | `{ "signed_statement_b64": "<COSE_Sign1, base64>" \| null }` | `ledger/signed-statements/<id>.cose` |
| `ledger/disclosure?capsule_id=<id>` | `{ "disclosure": {...} \| null }` | `ledger/disclosures/<id>.json` |
| `panes/pane-a` | pane A JSON (`api/sidecarTypes.ts` `PaneAJson`) | the ledger |
| `panes/pane-b` | pane B JSON (`PaneBJson`) | the ledger |
| `panes/pane-c[?limit=&after_seq=]` | pane C list (`PaneCListJson`) | the ledger |
| `panes/pane-c?exchange_id=<id>` | pane C drilldown (`PaneCDrilldownJson`) | the ledger |
| POST `tools/mesh_ledger_fetch` (a tool, not under `http/`) | the plugin's `mesh_ledger_fetch` tool: `LedgerFetchResponse` (`found` / `not_found` / `not_authorized` / `error`) | a peer's plugin, over a mesh stream |

**Split requests.** A `panes/pane-c` row may carry `split` (`api/sidecarTypes.ts`
`PaneCRow.split`, `lib/split-stage.ts` `SplitRowJson`):
`{ "viewer": "requester" | "coordinator", "main": <capsule>, "stage_records": [<capsule>...] }`,
the coordinator's main record and the stage records it carried (on a requester, from
`received-capsules.jsonl` and `received-split-stage-records.jsonl`), or
`{ "viewer": "stage", "stage_block": <x-mesh-stage-v1> }` on a stage node's own row. The page
runs the hand-off check itself (`verifySplit`) and draws the stage strip under the row. Rows
without `split` render as before. No pane emits it yet.

Status codes the page tells apart (`LedgerPage.tsx` `describePaneError`):
**404** means this plugin build serves no panes yet, and **503** means the
plugin's pane service isn't running. Any other failure gets the generic
message. A failed peer fetch renders as a transport error, never as a result.

## Where they are served

All of them are the plugin's own code: `src/evidence_routes.rs` declares the
six GET bindings, `src/evidence_panes.rs` builds the panes from the plugin's
ledger directory (padding left out of every count), and `src/ledger_fetch_bridge.rs` answers `mesh_ledger_fetch`.
`evidence_routes`'s manifest test pins the bindings. Fixture mode strips the
`http/` prefix and answers from recorded route captures.

## Console routes the page still reads

Two reads are the console's own data, not the plugin's:
`GET /api/status` (the owner link, and the peer list for the Peers tab's
"advertised" column) and `GET /api/models`. The page reads them with a
same-origin `fetch`, because the page is served from the console's origin.
They are public console routes, but a plugin page has no contract for them.
The console could withdraw or reshape them without notice, and they are
isolated in `features/network/api/` so the swap is one place. **Upstream ask
(host vocabulary):** a plugin-page read of node status (owner, peers) through
the host object, e.g. `host.node.status()`. The alternative is for the
plugin to serve peers from the mesh events it already subscribes to
(`peer_up`, `mesh_id_updated`).

Console navigation goes through `host.navigation.navigateTo`: `/chat`, and
the per-exchange `/logs?focusExchangeId=<id>`. The `focusExchangeId` search
parameter is not on upstream mesh-llm; there the link opens Logs unfocused.
