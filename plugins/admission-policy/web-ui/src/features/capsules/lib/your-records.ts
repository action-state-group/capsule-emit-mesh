// The Evidence hero's status line, ported from the mesh-llm console fork's
// `lib/your-records.ts` (`heroStatusLine` + `plural`, unchanged), and the
// `Clean up records` dialog's words (below, unchanged). The `Your records`
// panel is not here; see VENDORED.md.
import type { CleanupAction, CleanupResult, RecordsStatus } from '@/features/capsules/api/recordsClient'
import { SAMPLE_DATA_UNAVAILABLE, WITNESS_OFF } from '@/features/capsules/lib/tooltip-copy'

function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`
}

export type HeroCounts = {
  records: number
  confirmed: number
  disagreements: number
  /** A witness this node doesn't run holds a checkpoint. */
  witnessed: boolean
}

/** "8 records · 3 confirmed by the other side · 0 disagreements · checkable
 *  only by you (no witness)". The same counts the Integrity tiles show, from
 *  the same predicate, so the two can't disagree. */
export function heroStatusLine(counts: HeroCounts): string {
  return [
    plural(counts.records, 'record'),
    `${counts.confirmed} confirmed by the other side`,
    plural(counts.disagreements, 'disagreement'),
    counts.witnessed ? 'also held by a witness you don’t run' : `no outside witness (${WITNESS_OFF})`
  ].join(' · ')
}

// ---------------------------------------------------------------------------
// Clean up records: exactly three options, each with its consequence
// ---------------------------------------------------------------------------

export type CleanupOption = { action: CleanupAction; title: string; consequence: string; button: string }

export const CLEANUP_OPTIONS: readonly CleanupOption[] = [
  {
    action: 'delete_stored_text',
    title: 'Delete stored prompt and answer text',
    consequence:
      'Your records keep their fingerprints and stay valid. You can no longer show anyone the words of those exchanges.',
    button: 'Delete stored text'
  },
  {
    action: 'rebuild_index',
    title: 'Rebuild the index',
    consequence:
      'Re-reads and re-checks every record, and rebuilds what this node uses to look them up. Nothing is lost.',
    button: 'Rebuild index'
  },
  {
    action: 'start_new_log',
    title: 'Start a new log',
    consequence:
      'Your current records are archived whole, and a new log begins the next time this node starts. Nodes that already hold your checkpoint will see a new log, and anything you already shared stays with them.',
    button: 'Start a new log'
  }
] as const

/** Said once in the dialog, because the question will be asked. */
export const NO_SINGLE_RECORD_DELETE =
  'Records can’t be edited or removed one at a time. Removing one would break the chain, and anyone checking it would see that.'

export const CLEANUP_IS_ON_THE_RECORD = 'Each cleanup seals a record of itself onto your log.'

/** Why the run button can't act right now, or null when it can. */
/** Why "Delete stored prompt and answer text" is off: the prompts pill
 *  already says they are not kept, so there is nothing to delete. */
export const NO_STORED_TEXT = 'No prompt or answer text is kept, so there is nothing to delete.'

export function cleanupBlockedReason(
  action: CleanupAction,
  { sample, status, confirmed }: { sample: boolean; status: RecordsStatus | null; confirmed: boolean }
): string | null {
  if (sample) return SAMPLE_DATA_UNAVAILABLE
  if (!status) return 'This node didn’t answer, so nothing can be cleaned up from here.'
  if (action === 'delete_stored_text' && status.stored_text_count === 0) return NO_STORED_TEXT
  if (action === 'start_new_log') {
    if (status.new_history_pending) return NEW_LOG_PENDING
    if (!confirmed) return 'Tick the box above to confirm.'
  }
  return null
}

export const START_NEW_LOG_CONFIRM = 'I understand my current records will be archived and a new log will begin.'

export function cleanupResultMessage(result: CleanupResult): string {
  switch (result.action) {
    case 'delete_stored_text':
      return result.sealed
        ? `Deleted the stored text of ${plural(result.deleted_count, 'record')}. Sealed as record ${result.sealed.record_number}.`
        : 'There was no stored text to delete, so nothing was sealed.'
    case 'rebuild_index':
      return `Checked ${plural(result.records_checked, 'record')}; the index is rebuilt. Sealed as record ${result.sealed.record_number}.`
    case 'start_new_log':
      return `Sealed as record ${result.sealed.record_number}, the last of this log. The new log begins the next time this node starts.`
  }
}

export const NEW_LOG_PENDING = 'A new log begins the next time this node starts.'
