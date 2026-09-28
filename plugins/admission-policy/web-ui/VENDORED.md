# What is copied from the mesh-llm console

The Evidence page was the fork console's `/capsules` tab
(the mesh-llm console fork, `crates/mesh-llm-ui/src/features/capsules/**`). It moved
here from the mesh-llm console fork at commit e1319bdb99feb6b48ae02f217f5703915ccfaa47 (`round2-integration`), and the source
layout is kept (`@/` → `src/`), so each file diffs line-for-line against its
fork original. mesh-llm is Apache-2.0, as is this repository.

## The page (was the fork tab), `src/features/capsules/**`

Copied as-is except for these files:

| File | Change |
| --- | --- |
| `api/client.ts` | ledger reads go to this plugin's routes through `host.network.fetchPlugin` (JSON-wrapped); same exports and return shapes |
| `api/sidecarClient.ts` | pane reads go to this plugin's `panes/*` routes; `PaneFetchError` is the host seam's `PluginRouteError` |
| `api/peerLedgerFetchClient.ts` (+ test) | the tool route is plugin-relative (`tools/mesh_ledger_fetch`), so it now reaches `capsule-emit-mesh`; the fork addressed the retired name `admission-policy` |
| `pages/LedgerPage.tsx` | router `navigate` → `navigateHost`; the pane-error copy names the plugin (503) and adds the 404 "this plugin build doesn't serve its evidence panes yet" case |
| `components/ExchangeIdCell.tsx` | router `navigate` → `navigateHost('/logs?focusExchangeId=…')` |
| `lib/peer-mesh-status.ts` | calls the peers-only status adapter (below) |
| `lib/ledger-logs-non-overlap.test.ts` | the console's Logs column keys are pinned (they are console code) instead of imported |
| `retired-copy.test.ts` | scans every shipped source of the bundle; the host Rust pane scan stays with the pane on the fork until it moves here |
| `pages/EvidencePage.tsx` | **new**: the providers the console app supplied (query client, data mode fixed to live, tooltip provider) + `?focusExchangeKey=` |
| `pages/AccountabilityPage.tsx`, `pages/CapsulesExchangeRedirectPage.tsx` (+ test) | **removed**: console router glue; the deep link is `?focusExchangeKey=` on the plugin page |
| `lib/peer-routing-view.ts` (+ test) | **ported later** from the fork console's round-3 file: `dealingsLines` only (the drill's "Your dealings with them"); the block-store half needs the host's local block list, which this page does not reach |
| `components/PeerInspector.tsx` | the Overview shows "Your dealings with them" (`dealingsLines`) and a routing section that says plainly this page can't stop routing, in place of the console's Stop routing button |
| `lib/tooltip-copy.ts` | adds `YOUR_DEALINGS_TITLE` and `WITNESS_OFF` (console copy) and `ROUTING_NOT_ON_THIS_PAGE` |
| `lib/your-records.ts` (+ test) | **ported later**: `heroStatusLine` (the hero's one-line summary) and the `Clean up records` words, unchanged; the `Your records` panel is not ported |
| `components/CleanUpRecordsDialog.tsx` (+ test) | **ported later**, unchanged |
| `api/recordsClient.ts` | **ported later**: same types and calls; the tool route is plugin-relative through the host's `fetchPlugin` |
| `lib/use-your-records.ts` | **ported later**: the records-status query only (`useRecordsStatus`); the console's stored-text probe feeds a pill this page does not show |
| `lib/local-time.ts` | **ported later**, unchanged; row and drill times (`ExchangeStreamRow`, `PeerInspector`, `PeerExchangeInspector`) and the Integrity "no later than" line use it |
| `lib/entry-row-chips.ts`, `components/ExchangeRowChips.tsx` | the chips show the console's plain labels (`ENTRY_ROW_CHIP_LABEL`); the console's newer "covered" (◐) mark is not ported |
| `lib/peer-row-view.ts` | the Peers row's endpoint alias is cut to 16 characters, as in the console |
| `lib/integrity-view.ts` | plain words ahead of the console: "witnessed" (only when a witness holds a checkpoint) for "registered", local time, and the console's reworded owner-identity sentence |
| `pages/LedgerPage.tsx` | the hero line and the `Clean up records` button + dialog, as in the console |

## Console primitives the page imports

These are copied unchanged, so the page looks like the console: the
`src/components/ui/*` files, `src/lib/{cn,utils,env,vram,copyStateLabel,useClipboardCopy,format-model-size}.ts`,
`src/lib/api/*`, `src/lib/query/query-keys.ts`, `src/lib/data-mode/*`,
`src/lib/test/setup.ts`, `src/features/app-tabs/types.ts`,
`src/features/app-shell/lib/status-types.ts`, `src/features/chat/lib/chat-types.ts`,
and `src/features/network/api/*`, **except** `status-adapter.ts`, which is
cut to its peers-only subset. The page reads only `peers` from it, and the
dashboard half pulled in the console's dashboard fixtures.

The console styles these primitives with global component classes (e.g.
`surface-menu-panel`, `ui-control-ghost`) and theme tokens. Those classes
stay the console's: mounted in the console, the page uses them as they are.
Only Tailwind utilities are compiled into the page's own sheet
(`src/styles/evidence.css`).

## Re-syncing

When a console primitive changes upstream in a way the page should pick up,
copy the file again from mesh-llm-ui and re-run `pnpm typecheck && pnpm test`.
The page never imports console source at build time, so an upstream change
cannot break the installed bundle.
