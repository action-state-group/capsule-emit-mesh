// The words the page uses for a referee's verdict: on the twin bracket, on a
// judged node's row, on the referee's own row, and in the verdict record.
// Pure, so each sentence is unit-testable. A verdict is the referee's signed
// judgment, shown as it was sealed; the page never computes one.
import type {
  DeliveredAdjudication,
  IssuedAdjudication,
  VerdictRecordJson,
  VerdictWire
} from '@/features/capsules/api/sidecarTypes'

export type ParsedVerdict = { kind: 'corroborated' } | { kind: 'contradicted'; party: string }

export function parseVerdict(wire: VerdictWire | null | undefined): ParsedVerdict | null {
  if (wire === 'corroborated') return { kind: 'corroborated' }
  if (typeof wire === 'string' && wire.startsWith('contradicted:') && wire.length > 'contradicted:'.length) {
    return { kind: 'contradicted', party: wire.slice('contradicted:'.length) }
  }
  return null
}

/** Never a full 64-hex id on the page face: the first 10 characters. */
export function shortId(id: string): string {
  return id.length > 10 ? `${id.slice(0, 10)}…` : id
}

/** On a judged node's exchange row. */
export function deliveredVerdictLine(adjudication: DeliveredAdjudication): string | null {
  const verdict = parseVerdict(adjudication.verdict)
  if (verdict === null) return null
  const referee = `A referee (node ${shortId(adjudication.referee_node_id)})`
  if (verdict.kind === 'corroborated') return `${referee} found this answer corroborated.`
  return adjudication.about_this_node
    ? `${referee} found your answer contradicted.`
    : `${referee} found the other answer (node ${shortId(verdict.party)}) contradicted.`
}

/** On the referee node's row for the call it answered. */
export function issuedVerdictLine(issued: IssuedAdjudication): string | null {
  const verdict = parseVerdict(issued.verdict)
  if (verdict === null) return null
  const answers = issued.halves.length === 2 ? 'the two answers' : 'the answers'
  return verdict.kind === 'corroborated'
    ? `You judged ${answers}: corroborated.`
    : `You judged ${answers}: node ${shortId(verdict.party)}'s answer contradicted.`
}

export type VerdictRecordFacts = {
  verdict: ParsedVerdict | null
  halves: string[]
  refereeCapsuleId: string | null
}

/** The facts the verdict record itself holds, read off its sealed block. */
export function verdictRecordFacts(record: VerdictRecordJson): VerdictRecordFacts {
  const attestation = (record.capsule.model_attestation ?? null) as Record<string, unknown> | null
  const compute = (attestation?.compute_attestation ?? null) as Record<string, unknown> | null
  const block = (compute?.adjudication ?? null) as Record<string, unknown> | null
  const text = (key: string): string | null => (typeof block?.[key] === 'string' ? (block[key] as string) : null)
  const halves = [text('half_a_capsule_id'), text('half_b_capsule_id')].filter((id): id is string => id !== null)
  return {
    verdict: parseVerdict(text('verdict')),
    halves,
    refereeCapsuleId: text('referee_capsule_id')
  }
}

/** Whether the plugin could check the verdict's signature. */
export function verdictSignatureText(record: VerdictRecordJson): string {
  return record.verify_ok
    ? 'The referee’s signature checks, on this node.'
    : 'The referee’s signature does not check, on this node. Treat this verdict as unconfirmed.'
}
