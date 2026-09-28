// component-level enforcement of the
// observe-only/disclosure rules on top of the pure-function tests in
// `twin-bracket.test.ts`.
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import { TwinBracket } from '@/features/capsules/components/TwinBracket'
import type { ExchangeLedgerRow } from '@/features/capsules/lib/exchange-ledger'
import type { PaneCRow } from '@/features/capsules/api/sidecarTypes'

function twinRow(exchangeKey: string, overrides: Partial<PaneCRow> = {}): ExchangeLedgerRow {
  const raw: PaneCRow = {
    exchange_key: exchangeKey,
    role_tag: 'ASKED',
    header_state: 'ok',
    properties: null,
    has_issue: false,
    mine: { state: 'present', capsule_id: null },
    theirs: { state: 'present', capsule_id: null },
    unilateral: false,
    timestamp: '2026-09-14T00:00:00Z',
    twin_bracket_id: 'twin-xyz',
    ...overrides
  }
  return {
    exchangeKey: raw.exchange_key,
    timestamp: raw.timestamp,
    roleTag: raw.role_tag,
    counterparty: null,
    confirmed: false,
    hasIssue: false,
    checksText: '—',
    rightCellState: { kind: 'closed', date: null },
    contentToggleState: { your: { kind: 'populated', date: null }, their: { kind: 'not_asked', date: null } },
    sessionId: null,
    twinBracketId: raw.twin_bracket_id ?? null,
    raw
  }
}

describe('TwinBracket — v3 §5, OBSERVE-ONLY', () => {
  it('renders the TWIN header naming the bracket id, and its two children', () => {
    const rows = [twinRow('a'), twinRow('b')]
    render(
      <TwinBracket bracketId="twin-xyz" rows={rows} twinSampleRateDenominator={50}>
        <p>row a</p>
        <p>row b</p>
      </TwinBracket>
    )
    expect(screen.getByText(/TWIN · twin-xyz · same request, two peers/)).toBeInTheDocument()
    expect(screen.getByText('row a')).toBeInTheDocument()
    expect(screen.getByText('row b')).toBeInTheDocument()
  })

  it('LOAD-BEARING — item 4: never renders a verdict word (PASS/FAIL/identical/differs), only "no verdict"', () => {
    const rows = [
      twinRow('a', { mine: { state: 'present', capsule_id: null, text: 'same text' } }),
      twinRow('b', { mine: { state: 'present', capsule_id: null, text: 'same text' } })
    ]
    render(
      <TwinBracket bracketId="twin-xyz" rows={rows} twinSampleRateDenominator={50}>
        <p>row a</p>
        <p>row b</p>
      </TwinBracket>
    )
    expect(screen.getByText('no verdict')).toBeInTheDocument()
    expect(screen.queryByText(/\bPASS\b/)).not.toBeInTheDocument()
    expect(screen.queryByText(/\bFAIL\b/)).not.toBeInTheDocument()
    expect(screen.queryByText(/identical/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/\bdiffers\b/i)).not.toBeInTheDocument()
  })

  it('the disclosure sentence uses the LIVE rate prop, not a hardcoded 50', () => {
    const rows = [twinRow('a'), twinRow('b')]
    render(
      <TwinBracket bracketId="twin-xyz" rows={rows} twinSampleRateDenominator={2}>
        <p>row a</p>
        <p>row b</p>
      </TwinBracket>
    )
    expect(screen.getByText('This comparison ran automatically — 1 in 2 exchanges is sent to a second peer.')).toBeInTheDocument()
  })

  it('Compare is disabled when neither side has response text, and never renders as clickable-but-empty', () => {
    const rows = [twinRow('a'), twinRow('b')]
    render(
      <TwinBracket bracketId="twin-xyz" rows={rows} twinSampleRateDenominator={50}>
        <p>row a</p>
        <p>row b</p>
      </TwinBracket>
    )
    expect(screen.getByRole('button', { name: /Compare/ })).toBeDisabled()
  })

  it('Compare opens a real side-by-side diff of both peers\' response text when both sides have it', async () => {
    const user = userEvent.setup()
    const rows = [
      twinRow('a', { mine: { state: 'present', capsule_id: null, text: 'hello from A' } }),
      twinRow('b', { mine: { state: 'present', capsule_id: null, text: 'hello from B' } })
    ]
    render(
      <TwinBracket bracketId="twin-xyz" rows={rows} twinSampleRateDenominator={50}>
        <p>row a</p>
        <p>row b</p>
      </TwinBracket>
    )
    const button = screen.getByRole('button', { name: /Compare/ })
    expect(button).toBeEnabled()
    await user.click(button)
    expect(screen.getByText('Peer A response')).toBeInTheDocument()
    expect(screen.getByText('Peer B response')).toBeInTheDocument()
  })
})
