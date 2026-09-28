# Evidence page data routes

The Evidence page is a mesh-llm plugin page. The console's plugin web UI
contract lets a page reach its own plugin's routes, and only those, through
`host.network.fetchPlugin(path)`. The console serves them at
`/api/plugins/capsule-emit-mesh/<path>`. So the page reads **plugin-owned
routes only**. It never uses the fork console's host routes
(`/api/capsules/ledger/*`, `/api/capsules/panes/*`), which were never
upstream and never will be.

Plugin HTTP routes (`mesh_llm_plugin::http::get`) answer JSON, so data that
the fork served as raw files arrives wrapped in JSON.

| Plugin route (GET unless noted) | Answers | The fork host route it replaces |
| --- | --- | --- |
| `ledger` | `{ "records": [<capsule>...], "node_pub_key_pem": "<PEM>" \| null }`; 404 while nothing is sealed | `ledger/capsules.jsonl` + `ledger/node-key.pub.pem` |
| `ledger/signed-statement?capsule_id=<id>` | `{ "signed_statement_b64": "<COSE_Sign1, base64>" \| null }` | `ledger/signed-statements/<id>.cose` |
| `ledger/disclosure?capsule_id=<id>` | `{ "disclosure": {...} \| null }` | `ledger/disclosures/<id>.json` |
| `panes/pane-a` | pane A JSON, unchanged shape (`api/sidecarTypes.ts` `PaneAJson`) | `panes/pane-a` |
| `panes/pane-b` | pane B JSON, unchanged shape (`PaneBJson`) | `panes/pane-b` |
| `panes/pane-c[?limit=&after_seq=]` | pane C list, unchanged shape (`PaneCListJson`) | `panes/pane-c` |
| `panes/pane-c?exchange_id=<id>` | pane C drilldown (`PaneCDrilldownJson`) | `panes/pane-c?exchange_id=` |
| POST `tools/mesh_ledger_fetch` | the plugin's `mesh_ledger_fetch` tool: `LedgerFetchResponse` (`found` / `not_found` / `error`) | (already a plugin tool route on the fork, addressed to the old plugin name `admission-policy`) |

Status codes the page tells apart (`LedgerPage.tsx` `describePaneError`):
**404** means this plugin build serves no panes yet, and **503** means the
plugin's pane service isn't running. Any other failure gets the generic
message. A failed peer fetch renders as a transport error, never as a result.

## Not served yet

Every route above is **the page's contract, not yet the plugin's code**. On the
round-2 plugin (`round2-plugin-integration` @
331298a8b1ab517cacaf8f445f2d112bfe8ab4a9) none of them is served, and the
`mesh_ledger_fetch` tool is not on that base either. Installed today, the page
mounts and says so honestly. The console answers an undeclared plugin route
404 "No matching plugin HTTP binding" (mesh-llm-host-runtime
`api/routes/plugins.rs` `handle_stapled_http`, read from source; not run
against a host in this round), and the page reads that 404 as "This plugin
build doesn't serve its evidence panes yet." Fixture mode reproduces this with
an empty fixture set. Serving the routes takes three pieces of plugin work:

1. the `ledger*` routes read the plugin's own ledger directory. The plugin
   owns the files, so this is a small Rust change;
2. the `panes/*` routes: the pane reader, correlator and citing-record
   resolver currently live in the fork host (`capsule_panes_native.rs`,
   `build_pane_c_list`, `exchange_key_for`) and the Python sidecar. They
   move into the plugin, and the fork host's copies are deleted;
3. `tools/mesh_ledger_fetch` lands on this base.

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
parameter exists only on the fork console (commit e1319bdb99feb6b48ae02f217f5703915ccfaa47); on
stock upstream the link opens Logs unfocused.
