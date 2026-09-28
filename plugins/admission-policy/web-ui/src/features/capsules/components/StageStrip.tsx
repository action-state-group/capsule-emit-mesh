// The stage strip under a split request's row (design §7.2): one cell per
// stage, the hand-offs line, and the request's terminal state beside it.
// It is added beneath the row and never replaces the row's own state.
import { InfoHover } from '@/features/capsules/components/InfoHover'
import type { SplitRowJson } from '@/features/capsules/lib/split-stage'
import { splitView, stageRowHeadline } from '@/features/capsules/lib/split-stage'
import { SPLIT_TOOLTIPS } from '@/features/capsules/lib/tooltip-copy'

const HANDOFF_TONE: Record<string, string> = {
  agree: 'text-foreground',
  gap: 'text-fg-dim',
  break: 'text-[var(--color-danger)]',
  malformed: 'text-[var(--color-danger)]'
}

export function StageStrip({ split }: { split: SplitRowJson }) {
  if (split.viewer === 'stage') {
    return (
      <p className="type-caption font-mono text-fg-dim" data-split-stage-row="true">
        {stageRowHeadline(split.stage_block)}
      </p>
    )
  }
  const view = splitView(split)
  if (view === null) return null
  return (
    <div
      aria-label="Split stages"
      className="flex flex-col gap-1 rounded border border-border-soft px-3 py-2 font-mono text-xs"
      data-split-strip="true"
      role="group"
    >
      <p className="text-fg-dim">{view.headline}</p>
      <p className="inline-flex flex-wrap items-center gap-x-2 text-foreground">
        {view.cells.map((cell, i) => (
          <span data-stage-cell={cell.state} key={cell.stageIndex} title={cell.words}>
            {i > 0 ? <span className="text-fg-faint">· </span> : null}
            {cell.nodeId} {cell.layers}
            {cell.mark ? ` ${cell.mark}` : ''}
            {cell.state !== 'ok' ? <span className="text-fg-dim"> {cell.words}</span> : null}
          </span>
        ))}
        <InfoHover census="split:stage_cell" describes="the stage cells" label={SPLIT_TOOLTIPS.stageCell} />
      </p>
      <p className="inline-flex flex-wrap items-center gap-x-2">
        <span className="text-fg-faint">hand-offs:</span>
        {view.handoffs.map((item) => (
          <span className={HANDOFF_TONE[item.state]} data-handoff={item.state} key={item.label}>
            {item.label} {item.words}
            {item.state === 'agree' ? ' ✓' : ''}
          </span>
        ))}
        <span className="text-fg-faint">·</span>
        <span data-split-terminal-state={view.terminalState}>request: {view.terminalState.replace(/_/g, ' ')}</span>
        <InfoHover census="split:handoffs" describes="the hand-offs line" label={SPLIT_TOOLTIPS.handoffs} />
      </p>
    </div>
  )
}
