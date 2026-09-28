// v3 §4: every chip opens a four-part
// explanation -- what it means / what this view found (the input already
// rendered inline as `detail`) / what it does not establish / how to
// change it. The fourth part collapses to a fixed "nothing to do" sentence
// for facts that are immutable (`identity_authority`'s `authority`, or any
// property already `established`) -- an absent state instead names the
// concrete step that would supply it, never a generic "not yet".
import type { ChecksSideCell } from '@/features/capsules/lib/security-checks-view'

export type ChipExplanation = {
  whatItMeans: string
  whatThisFound: string
  whatItDoesNotEstablish: string
  howToChange: string
}

const NOTHING_TO_DO = 'Nothing to do — this is a fact about the record, not a problem.'

type StaticExplanation = {
  meaning: string
  doesNotEstablish: string
  /** Called only when the cell is not already `established` (`PASS`). */
  howToSupply: string
}

const STATIC: Record<string, StaticExplanation> = {
  content_binding: {
    meaning: 'The response bytes hash to the digest this record commits to.',
    doesNotEstablish: 'Who produced the response, or that the request itself was answered honestly.',
    howToSupply: 'Recompute runs automatically in your browser against the sealed bytes; there is nothing to ask for.'
  },
  producer_signature: {
    meaning: 'The signature over this record verifies against the claimed signing key.',
    doesNotEstablish: 'That the signing key belongs to a specific, accountable person or organisation.',
    howToSupply: 'Recompute runs automatically in your browser against the sealed bytes; there is nothing to ask for.'
  },
  task_binding: {
    meaning: 'The record names the specific task/model call it is an account of, not a generic placeholder.',
    doesNotEstablish: 'That the task description itself is accurate.',
    howToSupply: 'This comes from the sealed record as sent; there is no separate step to request it.'
  },
  local_inclusion: {
    meaning: 'This record is included in a checkpoint this node has registered.',
    doesNotEstablish: 'That the checkpoint itself has been registered anywhere a third party can see.',
    howToSupply: 'Register a checkpoint that covers this record’s range (see Integrity).'
  },
  checkpoint_signature: {
    meaning: 'The checkpoint covering this record carries a valid signature.',
    doesNotEstablish: 'That the checkpoint has been witnessed by anyone other than this node.',
    howToSupply: 'Register a checkpoint that covers this record’s range (see Integrity).'
  },
  external_registration: {
    meaning: 'An external witness has issued a receipt for the checkpoint covering this record.',
    doesNotEstablish: 'That the record’s content, not just its checkpoint, was reviewed by the witness.',
    howToSupply: 'Ask an external witness to register the checkpoint that covers this record.'
  },
  continuity: {
    meaning: 'This checkpoint binds to a prior registered checkpoint, so a rewrite between them would be detectable.',
    doesNotEstablish: 'That either checkpoint is true, only that a change between them would be visible.',
    howToSupply: 'Needs a registered checkpoint and a prior one to bind to (see Integrity).'
  },
  capture_coverage: {
    meaning: 'States the rule this node uses to decide which exchanges get captured at all.',
    doesNotEstablish: 'That every exchange the rule covers was captured without gaps.',
    howToSupply: 'This is a standing policy statement, not a per-record fact to request.'
  },
  outcome_corroboration: {
    meaning:
      'The counterparty has stated their own account of this exchange’s outcome, and it agrees with this side’s.',
    doesNotEstablish: 'That either side’s account of the outcome is itself accurate.',
    howToSupply: 'Ask the counterparty to state their half of this exchange.'
  },
  identity_authority_binding: {
    meaning: 'A key is bound to this node’s identity for this record.',
    doesNotEstablish: 'That the key belongs to a specific accountable person (see authority, below).',
    howToSupply: 'Bind an owner identity to this node (see Integrity).'
  },
  identity_authority_authority: {
    meaning: 'Whether a real person or organisation stands behind this node’s identity.',
    doesNotEstablish: 'Anything about this specific record -- this is a standing fact about the node.',
    howToSupply: NOTHING_TO_DO
  }
}

/** `factKey` disambiguates `identity_authority`'s two facts; omit for every
 *  other property. */
export function explanationFor(key: string, cell: ChecksSideCell, factKey?: 'binding' | 'authority'): ChipExplanation {
  const lookupKey = factKey ? `identity_authority_${factKey}` : key
  const entry = STATIC[lookupKey]
  if (!entry) {
    throw new Error(`chip-explanation.ts: no static explanation registered for "${lookupKey}"`)
  }
  return {
    whatItMeans: entry.meaning,
    whatThisFound: cell.detail,
    whatItDoesNotEstablish: entry.doesNotEstablish,
    howToChange: cell.state === 'PASS' ? NOTHING_TO_DO : entry.howToSupply
  }
}
