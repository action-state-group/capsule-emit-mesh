// Loose types over the capsule-emit-mesh sidecar's `GET /accountability/
// pane-a|b|c` JSON (L1, `accountability_pane_
// routes.py`) -- byte-for-byte the same payloads `capsule_accountability_
// tab.build_tab_payload` / `peer_accountability_tab.build_peers_payload` /
// `capsule_exchange_tab.build_exchange_list_payload`/`build_exchange_view`
// already produce, so these mirror THOSE shapes, not a new one. Deliberately
// permissive (optional/unknown-tolerant), same discipline as
// `api/types.ts`'s `CapsuleRecord` -- an unrecognised or absent field
// degrades to `undefined`, never a parse failure.
import type { CapsuleRecord, JsonRecord } from '@/features/capsules/api/types'
import type { SplitRowJson } from '@/features/capsules/lib/split-stage'

export type PaneState = { state: string; text?: string | null; [key: string]: unknown }

// ---------------------------------------------------------------------------
// Pane A ("This node") -- capsule_accountability_tab.build_tab_payload
// ---------------------------------------------------------------------------

export type PaneARow = {
  capsule_id: string
  timestamp: string | null
  model_claimed: string | null
  hardware_claimed: string | null
  verify_ok: boolean | null
  rungs: Record<string, PaneState>
  record: CapsuleRecord
  /** `counterparty_half_citation` on a record this node sealed to note a
   *  record received from the other side; absent on its own exchanges. */
  kind?: string | null
}

export type PaneAJson = {
  operator: string | null
  witness_checkpoint_supplied: boolean
  rows: PaneARow[]
  card: JsonRecord | null
}

// ---------------------------------------------------------------------------
// Pane B ("Peers") -- peer_accountability_tab.build_peers_payload. Field
// names below are read verbatim from `peer_accountability_tab.py` (build_
// peer_row / the *_cell functions) on capsule-emit-mesh main -- do not
// invent columns that function doesn't emit. Loose/optional per this file's
// own discipline: an unrecognised field degrades to `undefined`, not a
// parse failure.
// ---------------------------------------------------------------------------

/** `node_cell`. */
export type PaneBNodeCell = PaneState & {
  peer_id?: string | null
  member_kind?: string | null
  exchange_count?: number
}

/** `rung_cell`. `rung`/`distinct_rungs` are the raw ladder values
 *  (`unilateral_fallback` | `acknowledged_receipt` | `full_bilateral`) --
 *  never render the word "rung" itself (ledger grep gate). */
export type PaneBRungCell = PaneState & {
  rung?: string
  distinct_rungs?: string[]
}

/** `role_and_count_cell`. Direction-of-exchange fact, never a trust signal. */
export type PaneBRoleCell = PaneState & {
  role?: 'both' | 'you_to_them' | 'them_to_you' | 'unknown'
  you_to_them_count?: number
  them_to_you_count?: number
  exchange_count?: number
}

/** `peer_history_cell` ("History (theirs)"). Honestly NOT_CHECKED by
 *  default (no peer-fetch carrier wired on most sidecars yet) --
 *  `history_summary` only appears when `peer_fetch_result.status ===
 *  'verified'`. `mine_for_reference` is THIS node's own chain, carried
 *  along for reference only -- never presented as though it were the
 *  peer's. */
export type PaneBHistoryCell = PaneState & {
  fetch_source?: string
  history_summary?: {
    verified_bundles?: number | string
    checkpoint_count?: number | string
    [key: string]: unknown
  }
  mine_for_reference?: {
    history?: PaneState & { history_depth?: number; checkpoint_count?: number; cadence?: Record<string, unknown> }
    continuity?: PaneState & { unforked?: boolean }
    witnessed?: PaneState & { witnesses?: string[] }
    [key: string]: unknown
  } | null
}

/** `served_cell` ("Served (theirs)"). Same peer-fetch-gap discipline as
 *  `history`. */
export type PaneBServedCell = PaneState & {
  source?: string
  served_summary?: {
    n_served?: number | string
    n_completed?: number | string
    n_failed?: number | string
    [key: string]: unknown
  }
  mine_for_reference?: unknown
}

/** `pair_cell` ("Pair (me<->them)") -- digest reconciliation, real. The
 *  only cell that can say "missing" (a lone half with nothing to reconcile
 *  against). */
export type PaneBPairCell = PaneState & {
  verified?: number
  failed?: number
  missing?: number
  details?: Array<{ exchange_id: string; state: string }>
}

/** `verdicts_cell`. `tally` is real only for adjudications THIS node
 *  itself sealed -- "held by others" half is a separate pending reason.
 *  Never render `tally` without also stating the denominator it came
 *  from (`exchange_count`). */
export type PaneBVerdictsCell = PaneState & {
  tally?: { corroborated: number; contradicted: number; inconclusive: number }
  adjudication_capsule_id?: string
  references_tally?: { corroborated: number; contradicted: number; inconclusive: number }
  references_asked?: number
  references_answered?: number
}

/** `asked_cell` -- evidence requests THIS node sent to this peer. Absent
 *  by default (no send-log carrier yet on most sidecars). */
export type PaneBAskedCell = PaneState & {
  count?: number
  send_log?: unknown[]
}

/** One correlated push-primary counterparty half
 *  supplied to the ONE gate, per this peer's asked half that a
 *  provenance-carrying foreign sibling reconciles with
 *  (`capsule_panes_native.rs::confirmed_siblings_for`). Carries both bodies
 *  plus the door's recorded `signature_ok`, the inputs
 *  `exchange-row-state.ts::deriveRightCellState` judges -- so Pane B's
 *  "confirmed by the other side" / MATCH derive from the SAME gate Pane C uses,
 *  never a second browser-peer-fetch predicate. Empty on a peer with no
 *  correlated pushed half; the gate reads that as "not confirmed", honest. */
export type PaneBConfirmedSibling = {
  /** Our asked half, with its body (`mine_pair_cell`). */
  mine?: PaneCRow['mine']
  theirs: PaneCRow['theirs']
  digest_match?: PaneCRow['digest_match']
}

/** D3 -- ONE peer's alias evidence,
 *  joined on the signing key (`capsule_panes_native.rs::PeerIdentity`): the
 *  pushed body's own `key_id` (door-verified against the announced peer key),
 *  the door's `received_from` endpoint id, and a mesh node id only when a
 *  record actually names one. Each field is evidence-backed or null -- the UI
 *  renders these as aliases on one row, never as extra peers. Absent on an
 *  older payload; degrades to no alias line, never a fabricated identity. */
export type PaneBPeerIdentity = {
  signing_key_id?: string | null
  endpoint_id?: string | null
  node_id?: string | null
}

export type PaneBRow = {
  peer_id: string | null
  /** See `PaneBPeerIdentity`. */
  identity?: PaneBPeerIdentity | null
  node: PaneBNodeCell
  rung: PaneBRungCell
  role: PaneBRoleCell
  history: PaneBHistoryCell
  served: PaneBServedCell
  pair: PaneBPairCell
  /** See `PaneBConfirmedSibling`. Absent on an older sidecar that predates the
   *  push-primary path -- `confirmedByOtherSide` reads that as no correlated
   *  half, never a fabricated confirmation. */
  confirmed_siblings?: PaneBConfirmedSibling[]
  verdicts: PaneBVerdictsCell
  asked: PaneBAskedCell
  exchange_count: number
  first_seen: string | null
  last_seen: string | null
  expand?: {
    pair_ledger?: Array<{ exchange_id: string; state: string }>
    their_card?: PaneState
  }
  [key: string]: unknown
}

export type PaneBJson = {
  peer_count: number
  rows: PaneBRow[]
  [key: string]: unknown
}

// ---------------------------------------------------------------------------
// Pane C ("This exchange") -- capsule_exchange_tab.build_exchange_list_
// payload / build_exchange_view. The nine-property assurance map
// (`properties`) is the ONLY pane surface that carries the five-state chip
// strip today -- Pane A/B's `rungs`/cell states above are still the older
// per-rung ladder vocabulary (tone-compatible, not chip-shaped).
// ---------------------------------------------------------------------------

export type AssuranceProperties = Record<string, PaneState>

/** The four evidence-request outcomes named in the two-sided-ledger design
 *  note (v3 §2's "evidence" column) -- see `exchange-row-state.ts`. Optional
 *  because the carrier that would populate it is still unwired end-to-end
 *  (`evidence_responder.py`: "not yet reachable over the wire") -- an
 *  absent value degrades to `not_asked`, never a guess at one of the other
 *  three. */
export type EvidenceRequestOutcome = 'signed_refusal' | 'recorded_absence' | 'unanswered' | 'not_asked'

/** item 3 — the mechanical facts of an ambient
 *  twin comparison, when this row is one half of one. Deliberately carries
 *  NO computed verdict field (item 4: observe-only, no verdict published) --
 *  only what the two dispatches themselves recorded. Every field
 *  optional/forward-looking: no sidecar emits this yet (the host-side
 *  dispatch that would populate it is an unwired seam, see
 *  `runtime::twin_sample` on the Rust side), so it degrades to omission,
 *  never a fabricated comparison. */
export type TwinComparison = {
  temperature?: number | null
  seed?: number | null
  model_identity_hash?: string | null
  settings_label?: string | null
  response_digest?: string | null
}

export type PaneCRow = {
  exchange_key: string
  role_tag: string
  /** A split request's records (docs/DESIGN-split-stage-records.md §7): the
   *  coordinator's main record and the stage records it carried, or -- on a
   *  stage node's own row -- that stage's block. Absent on every other row.
   *  Not served yet; see DATA-ROUTES.md. */
  split?: SplitRowJson
  /** D4(a) -- the peer this row's own
   *  evidence names, using the SAME row key Pane B's peer rows use
   *  (`capsule_panes_native.rs::PeerAttribution`): the pushed sibling's
   *  identity, or -- on a requester-side row -- the server this node's own
   *  record routed to (`served_by_node_id`). Naming whom we asked is not a
   *  claim to hold their half; the right cell still derives independently.
   *  `null`/absent when no record names a peer -- never invented. */
  counterparty?: string | null
  header_state: string
  properties: AssuranceProperties | null
  has_issue: boolean
  mine: {
    state: string
    capsule_id: string | null
    role?: string
    text?: string
    /** What the counterparty streamed back to you -- held only on the
     *  requester's side (v3 §3: "both
     *  halves of the conversation are on the left, because both passed
     *  through you"). Optional/forward-looking: no sidecar emits it yet,
     *  degrades to omitting the second half rather than inventing one. */
    reply_text?: string
    reply_capsule_id?: string | null
    /** L-D: the requester's own copy of populated content, deleted locally.
     *  Only meaningful when `role_tag === 'ASKED'` -- a SERVED row's `mine`
     *  side was never populated to begin with (L-F). */
    deleted?: boolean
    deleted_date?: string | null
    /** OUR half's own body -- sent only on a correlated pushed pair
     *  (`capsule_panes_native.rs::mine_pair_cell`), so the gate compares the
     *  counterparty half against our real digests + `served_by_node_id`. */
    record?: Record<string, unknown>
  }
  theirs: {
    state: string
    capsule_id: string | null
    role?: string
    text?: string
    evidence_outcome?: EvidenceRequestOutcome
    evidence_outcome_date?: string | null
    /** piece 3 -- the mesh peer id to fetch FROM
     *  (`capsule_panes_native.rs::theirs_cell`'s `served_by_node_id`),
     *  present only alongside `theirs.state === 'NOT_CHECKED'` and a real
     *  `capsule_id`. Never guessed: `null`/absent means this row carries no
     *  fetchable join key, same "never fabricate" discipline as every other
     *  optional field in this file. */
    peer_id?: string | null
    /** The record-push door's provenance triple
     *  for a locally-held, identity-verified counterparty half
     *  (`capsule_panes_native.rs::theirs_sibling_cell`, read off OUR citing
     *  record's `received_half`). `signature_ok` is the door's recorded
     *  verdict of the peer-key signature check -- one of the ONE gate's four
     *  CLOSED conditions, never sufficient alone. Absent on every row with no
     *  citing record; a self-sealed / provenance-less sibling never carries
     *  it, so it never closes. */
    signature_ok?: boolean
    received_from?: string
    via?: string
    received_at?: string
    /** The held foreign body itself -- the provider-signed bytes the door
     *  verified (`capsule_panes_native.rs::theirs_sibling_cell`). Present only
     *  on a correlated pushed half; the gate recomputes its `capsule_id` and
     *  compares its digests + provider against OUR half. */
    record?: Record<string, unknown>
    /** Whether `record` recomputes to `capsule_id`, computed IN THIS BROWSER
     *  by `attachPushedHalfRecompute` before the pane query resolves (never
     *  sent by the host). `null` when the recompute could not run; absent
     *  until it has run. */
    id_match?: boolean | null
  }
  unilateral: boolean
  /** The STRUCTURAL digest reconciliation of a
   *  correlated pair (`capsule_panes_native.rs::digest_match_state`) -- both
   *  halves' `effect.request_digest`/`effect.response_digest` compared
   *  field-by-field. Display-only: the ONE gate (`exchange-row-state.ts`)
   *  compares the two bodies itself and does not read this. Absent on a
   *  unilateral row (nothing to reconcile). */
  digest_match?: { state: 'verified' | 'failed' | 'absent' | 'present-unverified' }
  timestamp: string | null
  /** The conversation this exchange belongs to, when this node was the
   *  requester (v3 §2 L-O: a served row structurally has none -- this node
   *  was never party to the requester's session). Optional/forward-looking:
   *  no sidecar emits it yet, so it degrades to `null` (no rail), never an
   *  invented grouping. */
  session_id?: string | null
  /** item 2 — the id shared by BOTH halves of an
   *  ambient twin comparison, minted host-side (Rust) per the ticket's
   *  Rust-native ruling. `null`/absent on every row that wasn't ambiently
   *  twinned (the overwhelming majority) -- optional/forward-looking, same
   *  discipline as `session_id`: no sidecar emits it yet, degrades to no
   *  bracket rather than a half-bracket. */
  twin_bracket_id?: string | null
  /** The comparison facts for this row's half of the bracket -- see
   *  `TwinComparison`. Present only alongside a real `twin_bracket_id`. */
  twin_comparison?: TwinComparison | null
}

export type PaneCListJson = {
  row_count: number
  default_sort: string
  filters: string[]
  rows: PaneCRow[]
  next_after_seq: number | null
  archived_segments: unknown[]
  /** item 3 — the LIVE configured ambient-twin
   *  sample rate expressed as "1 in N", for the disclosure sentence
   *  ("This comparison ran automatically — 1 in N exchanges is sent to a
   *  second peer."). Optional/forward-looking: no sidecar emits it yet
   *  (the Rust host's `twin_sample::configured_twin_sample_rate` isn't
   *  wired to a live status endpoint this session) -- a bracket still
   *  renders without it, just without a specific N in the sentence, never
   *  a hardcoded "50". */
  twin_sample_rate_denominator?: number | null
}

export type PaneCDrilldownJson =
  | { exchange_key: string; found: false }
  | { exchange_key: string; found: true; view: JsonRecord & { properties?: AssuranceProperties; capsule_id?: string } }
