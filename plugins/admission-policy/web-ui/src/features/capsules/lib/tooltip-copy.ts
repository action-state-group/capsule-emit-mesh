// The Evidence tab's hover copy, in one place (
// UX review §8). One tooltip per chip TYPE, shared by every instance of it, so
// the census test (`tooltip-census.test.tsx`) can check each one: present,
// one plain sentence or two, no retired phrase, and -- outside Dig (the checks
// panel) -- none of the engineer's words ("half", "capsule id", "leaves",
// "recomputed"). Say what a thing is, never what it isn't: a banned word stays
// off the screen even to deny it.
//
// The Peers column and Integrity tile NAMES are unchanged here; their renames
// land with the plain-language pass. Every sentence below reads
// correctly under either name.

/** Hero chips (the InfoBanner's status row). */
export const HERO_TOOLTIPS = {
  live: 'Reading this node’s records over its running local API. They update as this node seals them.',
  local: 'Reading a saved local copy. This node’s API is not connected, so the records are not updating.',
  sample: 'Showing a saved sample run, not this node’s records. Nothing here updates.',
  // §8 adds "Open to see where they are and what you share." -- held back
  // until the pill opens something (rule 5: never ask for what can't be done).
  yourRecords: 'The records this node keeps, sealed and checkpointed. Open to see where they are and what you share.'
} as const

/** p2 item 3: the owner-link fact, worded once for Integrity's step 2 and
 *  the checks panel's binding fact. */
export const OWNER_LINKED_PHRASE = 'linked to your owner account (self-asserted)'
export const OWNER_NOT_LINKED_PHRASE = 'not linked to an owner'

/** p2 item 5: why an action is disabled -- said on hover, never a silent grey. */
export const SAMPLE_DATA_UNAVAILABLE = 'Not available on sample data.'
export const NO_CONTRADICTION_REASON = 'No contradicted exchange to jump to.'

/** The InfoBanner description under the tab title: what the page holds, and
 *  what can be shown about it. "docs" links the trust map (`TRUST_MAP_URL`). */
export const HERO_DESCRIPTION_BEFORE_LINK =
  'Evidence: every exchange this node sealed at the moment it happened. A sealed record cannot change without it showing. Depending on what is turned on, it can also be shown to sit in a signed checkpoint, be witnessed by an outside log, and match the other side’s record. The chips on each row say which of these were checked here. See the '
export const HERO_DESCRIPTION_LINK_TEXT = 'docs'
export const HERO_DESCRIPTION_AFTER_LINK = ' for the full trust map.'
export const HERO_DESCRIPTION = `${HERO_DESCRIPTION_BEFORE_LINK}${HERO_DESCRIPTION_LINK_TEXT}${HERO_DESCRIPTION_AFTER_LINK}`

/** Where "docs" in the hero points: this plugin's trust model. */
export const TRUST_MAP_URL = 'https://github.com/action-state-group/capsule-emit-mesh/blob/main/docs/TRUST-MODEL.md'

/** Peers table column headers. */
export const PEER_COLUMN_TOOLTIPS = {
  exchanges: 'Distinct exchanges with this peer. Your record and theirs of the same exchange count once.',
  confirmed: 'How many of your exchanges with them are confirmed by their own signed record, checked on this machine.',
  match:
    'How many of their records hold the same request and answer as yours, and how many disagree, including records your node refused for naming another server or model.',
  adjudication:
    'Verdicts sealed about this peer’s answers, and how many exchanges they looked at. None means no verdict has been sealed about this peer.',
  witness:
    'Whether this peer’s records are held by a witness they don’t run. Not shown yet: this view doesn’t have that data.',
  period: 'The date of your latest exchange with this peer.'
} as const

/** The Peers row's alias line, and the table's second group. */
export const PEER_ALIAS_TOOLTIP =
  'The ids this peer uses: the key it signs with, its mesh node and its endpoint, as they appear on your records.'
export const ADVERTISED_UNUSED_TOOLTIP = 'Nodes the mesh told you about that you haven’t exchanged with.'
export const PEER_NEEDS_A_LOOK_LABEL = 'Needs a look'

/** The peer's self-reported identity note. */
export const SELF_REPORTED_TOOLTIP =
  'This identity is self-reported: it’s what the peer says about itself. Only the records they signed, checked on this machine, count as evidence.'

/** The one line at the top of the old peer inspector, until the new peer
 *  drill replaces it. */
export const PEER_INSPECTOR_HEADER = 'What you’ve recorded with this peer. Their own log and what others say come next.'

/** Peer attention badges -- the specific thing, counted, replacing the old
 *  generic ⚠ alarm chip. Each is one sentence naming exactly that. */
export const PEER_ATTENTION = {
  disagreements: {
    label: (n: number) => `${n} disagreement${n === 1 ? '' : 's'}`,
    tooltip: (n: number) => `${n} exchange${n === 1 ? '' : 's'} where your record and theirs disagree.`
  },
  differingAnswers: {
    label: (n: number) => `${n} differing answer${n === 1 ? '' : 's'}`,
    tooltip: (n: number, when?: string | null) =>
      `${n === 1 ? '1 comparison your node sealed' : `${n} comparisons your node sealed`} found this peer’s answer differed from another machine’s.${
        when ? ` Latest: ${when}.` : ''
      }`
  },
  logFailed: {
    label: () => 'log didn’t check out',
    tooltip: () => 'Your node fetched their log and it failed its checks on this machine.'
  },
  refused: {
    label: () => 'refused a request',
    tooltip: () => 'They declined a request and signed the refusal.'
  }
} as const

/** The row's state badge: the (i) beside CLOSED / CONTRADICTED / OPEN. */
export const ROW_STATE_TOOLTIPS = {
  closed:
    'They sent their own signed record of this exchange, from the node that served you, and it checks out on this machine. It names the same request, answer and model weights as yours.',
  contradicted:
    'You both have signed records of this exchange and they disagree: the request, the answer, the model or who served it differs, or their record doesn’t match its own id. Use Compare to see where.',
  open_refused:
    'They declined to share their record and signed the refusal. The refusal is the evidence; the exchange stays open.',
  open_absent:
    'They say they have no record of this exchange. That is their statement; there is nothing of theirs to check.',
  open_asked: 'You asked for their record and no reply has arrived yet.',
  open_not_held:
    'Their record hasn’t arrived, or what arrived couldn’t be confirmed as theirs from the node that served you. It usually comes when the exchange finishes.',
  open_not_given: 'Their record of this exchange hasn’t arrived yet, and they didn’t send an id to ask for it by.',
  open_not_asked: 'You haven’t asked them for their record.'
} as const

/** The per-property cells a CLOSED row shows, each with its own (i). */
export const CLOSED_CELL_TOOLTIPS = {
  their_id: 'The id of their record; it’s a fingerprint of the record itself.',
  signature: 'Signed with the key this peer announces.',
  request: 'The same request as in your record.',
  response: 'The same answer as in your record.'
} as const


/** The chip strip, per result: what a ✓, ✗ or – on each chip means, and
 *  the check behind it. The words-match and signed chips are checked on this
 *  machine (recompute-identity.ts); in-a-checkpoint is the node's count, not
 *  a checked proof; witnessed is read, not checked here. */
export const ENTRY_CHIP_RESULT_TOOLTIPS = {
  content: {
    '✓': 'Your record’s fingerprint, checked on this machine, still equals the id it was sealed with, so nothing in it has changed.',
    '✗': 'Your record no longer matches its id, so it changed after it was sealed. Save the evidence file and check this node’s storage.',
    '–': 'Not checked yet: this page hasn’t loaded your record.'
  },
  sig: {
    '✓': 'The signature on your record checks against this node’s key, on this machine.',
    '✗': 'The signature on your record doesn’t check against this node’s key.',
    '–': 'Not checked: the signed copy or this node’s key isn’t available to this page.'
  },
  inclusion: {
    '✓': 'A checkpoint this node signed covers this record, by the node’s own count. This page doesn’t check that coverage itself.',
    '✗': 'The node reports that no checkpoint covers this record.',
    '–': 'No checkpoint covers this record yet; the next checkpoint the node makes will.'
  },
  registered: {
    '✓': 'A witness you don’t run holds a checkpoint covering this record. The witness’s receipt isn’t checked on this page.',
    '✗': 'The node reports that no witness holds a checkpoint covering this record.',
    '–': 'No witness you don’t run holds a checkpoint covering this record. Not checked here.'
  },
  theirs: {
    '✓': 'Confirmed: their own signed record, from the node that served you, names the same request, answer and model weights as yours.',
    '✗': 'Their signed record disagrees with yours, or doesn’t match its own id. The state on the right says more.',
    '–': 'No confirmed record from them yet; the state on the right says why.'
  }
} as const

/** A row confirmed from a record this page asked for and fetched: honest
 *  that nothing was saved on the node (console copy). */
export const CLOSED_FROM_FETCH_NOT_SAVED =
  'Confirmed on this page from the record you asked for; not saved on this node yet.'

/** A confirmed exchange whose own record fails its checks: said on the row,
 *  so a Confirmed badge never sits beside a failed check unexplained. */
export const OWN_RECORD_FAILS_WARNING =
  'Your own copy of this record fails its checks, so neither side can rely on it, whatever the badge says.'

/** The side-by-side check (the twin bracket): its hovers. The answer
 *  comparison is this node's plugin comparing the two sealed answer
 *  fingerprints (evidence_panes.rs attach_twins); a verdict is a referee's
 *  signed record, read here, its signature checked by the plugin. */
export const TWIN_TOOLTIPS = {
  header: 'Your node sent the same request to two machines and kept both answers, so they can be compared.',
  same: 'The two machines’ answers have the same fingerprint, compared by this node. That is not a verdict.',
  different: 'The two machines’ answers have different fingerprints, compared by this node. That alone doesn’t say which is wrong.',
  not_compared: 'Not compared yet: one of the two answers’ fingerprints hasn’t reached this node.',
  verdict: 'A referee’s signed verdict on this pair. Open it to see whether its signature checks on this node.',
  parameters: 'The settings both machines were asked to use; a difference here can explain a different answer.',
  compare: 'Show the two answers side by side. This page doesn’t judge them.',
  save: 'Download both records of this side-by-side check as a file.'
} as const

/** The side-by-side check's verdict badge, per ruling the referee sealed. */
export const TWIN_VERDICT_TOOLTIPS = {
  corroborated: 'A referee compared the two answers, found they agree, and signed that verdict. Open it to see whether its signature checks here.',
  contradicted: 'A referee compared the two answers, found one wrong, and signed that verdict. Open it to see whether its signature checks here.',
  inconclusive: 'A referee compared the two answers and couldn’t decide between them. That is not a disagreement.',
  not_comparable: 'The two answers were sampled, so a referee can’t compare them. This is never a disagreement.'
} as const

/** The TWIN bracket's `no verdict` badge. */
export const TWIN_NO_VERDICT_TOOLTIP =
  'The same request went to two machines and both answers are recorded. No one has compared them and sealed a verdict yet.'

/** Integrity tiles. */
export const INTEGRITY_TILE_TOOLTIPS = {
  sealed:
    'Records this node sealed into its log, not counting padding. Sealed means a record can’t change unnoticed; it doesn’t make the contents true.',
  sharedWithWitness:
    'How many of your checkpoints a witness you don’t run is holding. Off by your choice until you turn one on.',
  confirmedByOtherSide: 'Exchanges the other side confirmed with their own signed record, checked on this machine.',
  contradicted:
    'Exchanges where your record and theirs disagree: a different request, answer, model or server, or their record not matching its own id.'
} as const

/** The Exchanges header's one setup button: it opens Integrity and does
 *  nothing else, so the hover says exactly that. */
export const SETUP_STEPS_LABEL = 'See the setup steps'
export const SETUP_STEPS_TOOLTIP =
  'Opens Integrity, which lists how to get the other side’s record and how to have a witness hold your checkpoints.'

/** Integrity: Continuity, and the evidence file download. */
export const CONTINUITY_TOOLTIP =
  'Whether each checkpoint builds on the one before, so a rewrite would show. This page reads the node’s status and doesn’t check it.'
export const SAVE_EVIDENCE_FILE_TOOLTIP =
  'Download this node’s records and checkpoint facts as one file that anyone can check without this app.'

/** Integrity's chain coverage strip. */
export const CHAIN_STRIP_TOOLTIP =
  'Shaded: records sealed into a checkpoint. Unshaded: records sealed since the last checkpoint.'

/** The checks panel's chips (Dig), one per property. Hover for the meaning;
 *  a click still opens the four-part explanation (v3 §4). Dig may use the
 *  exact terms, but each hover is still one plain sentence. */
export const CHECK_CHIP_TOOLTIPS: Record<string, string> = {
  content_binding: 'Whether the record’s contents still match its id.',
  producer_signature: 'Whether the record is signed with the key its node announces.',
  task_binding: 'Whether the record is tied to the request it answers.',
  local_inclusion: 'Whether a checkpoint on the node that sealed it covers this record.',
  checkpoint_signature: 'Whether that checkpoint is signed by the node that made it.',
  external_registration: 'Whether a witness that node doesn’t run holds the checkpoint.',
  continuity: 'Whether that checkpoint binds to the one before it.',
  outcome_corroboration: 'Whether the other side’s own record confirms what happened.',
  'identity_authority:binding': 'Whether the signing key is bound to an owner identity.',
  'identity_authority:authority': 'Whether that owner identity is bound to a person.'
}

export function checkChipTooltipKey(propertyKey: string, factKey?: 'binding' | 'authority'): string {
  return factKey ? `${propertyKey}:${factKey}` : propertyKey
}

/** A split request's stage strip (docs/DESIGN-split-stage-records.md §7.2).
 *  Face copy: plain words, and `agree` never claims more than the records do.
 *  Which node ran which stage is the coordinator's word: a stage record's key
 *  is not linked to a node on this page, so the copy says so. */
export const SPLIT_TOOLTIPS = {
  stageCell:
    'The coordinator says which node ran each stage. A tick means that stage’s record matches what the coordinator assigned it.',
  handoffs:
    'The records at both ends of each hand-off name the same data. It says the two records agree, not which node signed them, that the nodes are independent, or that any layer was computed correctly.',
  throughSplit:
    'Nodes the coordinator says ran part of a request you sent it. You never dealt with them directly.'
} as const

/** The stage strip: one hover per cell state and per hand-off state. */
export const STAGE_CELL_TOOLTIPS = {
  coordinator_slice: 'The part of the request the coordinator ran itself.',
  ok: 'This stage’s record matches what the coordinator assigned it.',
  disagrees: 'This stage’s record doesn’t match what the coordinator assigned it.',
  not_received: 'No record from this stage reached you.',
  not_requested: 'This stage wasn’t part of the run.',
  conflict: 'Two different records claim this stage; one of them is wrong.',
  rejected: 'A record here is broken or isn’t a valid record of this stage, so it can’t be read.'
} as const

export const HANDOFF_TOOLTIPS = {
  agree: 'The records at both ends of this hand-off name the same data.',
  gap: 'One end of this hand-off has no record.',
  break: 'The two ends of this hand-off name different data.',
  malformed: 'A record at this hand-off is broken and can’t be read.'
} as const

/** §7.5: the drill's "your dealings with them" section title (console copy). */
export const YOUR_DEALINGS_TITLE = 'Your dealings with them'

/** The drill's routing section. Stopping routing to a peer needs the host's
 *  local block list, which this page does not reach, so the page says so
 *  instead of offering a button that could not act. */
export const ROUTING_NOT_ON_THIS_PAGE = {
  sectionTitle: 'Routing to this peer',
  text: 'This page can’t stop routing to a peer. It shows your records and changes nothing about routing.'
} as const

/** The hero line's words when no witness holds a checkpoint (console copy). */
export const WITNESS_OFF = 'witness off — your choice'
