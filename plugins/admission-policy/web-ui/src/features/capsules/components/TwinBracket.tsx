// The TWIN bracket wrapper (v3 §5): a header
// naming the bracket, the two (or more) real two-sided rows it brackets
// (passed as `children`, already-rendered `ExchangeStreamRow`s -- this
// component adds chrome around them, it does not re-derive their content),
// and a COMPARISON block below.
//
// OBSERVE-ONLY (item 4): no verdict renders here, ever -- not PASS, not
// FAIL, not "identical." The header status is always the honest
// "no verdict" state, and the COMPARISON block states plainly that
// adjudication is not yet enabled. This stays true even once real
// parameters/digests are wired (see `twin-bracket.ts`) -- computing an
// equality verdict from a digest match is a deliberate product decision, not a
// default this component reaches on its own.
import { useState } from 'react'
import ReactDiffViewer from 'react-diff-viewer-continued'
import { Button } from '@/components/ui/button'
import { StatusBadge } from '@/components/ui/StatusBadge'
import type { ExchangeLedgerRow } from '@/features/capsules/lib/exchange-ledger'
import { saveTextFile } from '@/features/capsules/lib/exchange-export'
import { InfoHover } from '@/features/capsules/components/InfoHover'
import { TWIN_NO_VERDICT_TOOLTIP } from '@/features/capsules/lib/tooltip-copy'
import {
  TWIN_ANSWER_LABEL,
  twinAnswerState,
  twinComparisonParametersLine,
  twinDisclosureSentence,
  twinResponseTexts,
  twinVerdict
} from '@/features/capsules/lib/twin-bracket'

const diffViewerStyles = {
  diffContainer: {
    background: 'var(--color-panel)',
    border: '1px solid var(--color-border-soft)',
    borderRadius: 'var(--radius)',
    minWidth: '100%',
    width: '100%',
    fontSize: 'var(--density-type-caption)',
    color: 'var(--color-foreground)'
  },
  titleBlock: {
    background: 'var(--color-panel-strong)',
    color: 'var(--color-fg-dim)',
    borderBottom: '1px solid var(--color-border-soft)'
  }
}

export type TwinBracketProps = {
  bracketId: string
  rows: readonly ExchangeLedgerRow[]
  /** The LIVE configured "1 in N" ambient-twin rate -- see
   *  `twinDisclosureSentence`'s own doc for why this must never default to
   *  a hardcoded constant inside this component either. */
  twinSampleRateDenominator: number | null
  children: React.ReactNode
}

export function TwinBracket({ bracketId, rows, twinSampleRateDenominator, children }: TwinBracketProps) {
  const [compareOpen, setCompareOpen] = useState(false)
  const parametersLine = twinComparisonParametersLine(rows)
  const disclosure = twinDisclosureSentence(twinSampleRateDenominator)
  const [textA, textB] = twinResponseTexts(rows)
  const canCompare = textA !== null && textB !== null
  const answer = twinAnswerState(rows)
  const { verdict, capsuleId } = twinVerdict(rows)

  const handleSave = () => {
    saveTextFile(`twin-bracket-${bracketId}.json`, JSON.stringify(rows.map((row) => row.raw), null, 2), 'application/json')
  }

  return (
    <div
      aria-label={`Twin comparison ${bracketId}`}
      className="flex flex-col border-2 border-[var(--color-accent)]/40"
      data-testid={`twin-bracket-${bracketId}`}
      role="group"
    >
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border-soft bg-panel-strong/60 px-3 py-1.5">
        <p className="type-caption font-mono font-medium text-fg-dim">TWIN · {bracketId} · same request, two peers</p>
        <span className="inline-flex items-center gap-1">
          {/* A checked fact (the two sealed answer-text digests), never a verdict. */}
          <StatusBadge size="caption" tone={answer === 'different' ? 'warn' : 'muted'}>
            {TWIN_ANSWER_LABEL[answer]}
          </StatusBadge>
          {verdict === null ? (
            <>
              <StatusBadge size="caption" tone="muted">
                no verdict
              </StatusBadge>
              <InfoHover census="twin:no_verdict" describes="the no verdict badge" label={TWIN_NO_VERDICT_TOOLTIP} />
            </>
          ) : (
            <StatusBadge size="caption" tone={verdict.kind === 'contradicted' ? 'bad' : 'good'}>
              {verdict.kind === 'contradicted' ? `referee: contradicted ${verdict.party.slice(0, 10)}…` : 'referee: corroborated'}
            </StatusBadge>
          )}
        </span>
      </div>

      <div className="flex flex-col divide-y divide-border-soft">{children}</div>

      <div className="flex flex-col gap-1.5 border-t border-border-soft bg-panel-strong/40 px-3 py-2">
        <p className="type-caption font-mono text-fg-dim">COMPARISON</p>
        {parametersLine ? <p className="type-caption text-fg-faint">{parametersLine}</p> : null}
        {/* OBSERVE-ONLY -- this line NEVER renders "identical"/"differs" or
           any other computed verdict, only the honest state of adjudication
           itself. */}
        {verdict === null ? (
          <p className="type-caption text-fg-faint">
            Not yet adjudicated — no referee has signed a verdict for this pair.
          </p>
        ) : (
          <p className="type-caption text-fg-faint">Referee's signed verdict: {capsuleId ? `${capsuleId.slice(0, 12)}…` : 'id not recorded'}</p>
        )}
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="type-caption text-fg-faint">{disclosure}</p>
          <div className="flex items-center gap-1">
            <Button
              disabled={!canCompare}
              onClick={() => setCompareOpen((open) => !open)}
              size="sm"
              title={canCompare ? undefined : 'Neither side has response text to compare yet.'}
              type="button"
              variant="outline"
            >
              {compareOpen ? 'Compare ▾' : 'Compare ▸'}
            </Button>
            <Button onClick={handleSave} size="sm" type="button" variant="outline">
              ⧉ Save
            </Button>
          </div>
        </div>
        {compareOpen && canCompare ? (
          <div className="mt-1 overflow-hidden rounded border border-border-soft">
            <ReactDiffViewer
              leftTitle="Peer A response"
              newValue={textB ?? ''}
              oldValue={textA ?? ''}
              rightTitle="Peer B response"
              splitView
              styles={diffViewerStyles}
            />
          </div>
        ) : null}
      </div>
    </div>
  )
}
