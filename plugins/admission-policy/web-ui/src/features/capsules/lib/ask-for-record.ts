// "Ask them for their record" (UX §3): after the timeout, a row whose other
// side's record hasn't arrived can ask that node for it. The host sends one
// evidence request over the mesh (`api/evidenceRequestClient.ts`); this module
// judges what came back, the same way the row judges a record that was
// pushed: nothing here is trusted because it arrived.
//
//   - a refusal counts only if it is signed with the key this node was told
//     the peer signs with (`announcedKeyId`, never the key the refusal names
//     itself) and it names OUR request (`request_digest` = the digest of the
//     bytes we sent): a throwaway key or a refusal replayed from another
//     request proves nothing. `no_such_record` is their signed "I have no
//     record of this", any other
//     reason is a signed decline, except `coverage_unsatisfiable`: they hold
//     the record but can't prove it yet (no checkpoint covers it), so the row
//     stays asked and can ask again;
//   - a record goes through THE row gate (`deriveRightCellState`) as a fetched
//     half: it closes the row only if its id recomputes, its signature
//     verifies under the announced key, it came from the node that served us
//     and both digests equal ours;
//   - with no announced key for the peer, nothing it sends can be checked:
//     the row stays asked;
//   - no answer, or an answer that proves nothing, leaves the row "asked, no
//     reply yet".
import { ed25519 } from '@noble/curves/ed25519'
import type { PaneCRow } from '@/features/capsules/api/sidecarTypes'
import type { CapsuleRecord } from '@/features/capsules/api/types'
import type { EvidenceAskReply } from '@/features/capsules/api/evidenceRequestClient'
import { verifyCoseSign1 } from '@/features/capsules/lib/cose'
import {
  askForRecordIsDue,
  deriveRightCellState,
  type RightCellState,
  type RightCellStateKind
} from '@/features/capsules/lib/exchange-row-state'
import { recomputeIdMatch, type PeerRecomputeState } from '@/features/capsules/lib/recompute-identity'

/** What asking produced for one row. `at` is when this node asked or when the
 *  other side signed its reply. */
export type AskOutcome =
  | { kind: 'asking'; at: string }
  | { kind: 'no_reply'; at: string; detail: string }
  | { kind: 'refused'; at: string; reason: string }
  | { kind: 'no_record'; at: string }
  | { kind: 'record'; at: string; evidence: PeerRecomputeState }

/** Whom to ask and how to name the exchange, read from OUR record of it: the
 *  node that served our request (or that asked us, on a row we served), and
 *  the client nonce both records carry. `null` when either is unknown. */
export type AskTarget = { peerId: string; nonce: string }

const FULL_ID = /^[0-9a-f]{64}$/
const NO_SUCH_RECORD = 'no_such_record'
/** They hold the record but no checkpoint covers it yet: a lag, never a
 *  decline. Asking again later can succeed. */
const COVERAGE_LAG = 'coverage_unsatisfiable'

function obj(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : null
}

function str(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null
}

function pocBlock(record: unknown): Record<string, unknown> | null {
  return obj(obj(obj(obj(record)?.model_attestation)?.compute_attestation)?.['x-mesh-poc-v1'])
}

export function askTarget(record: CapsuleRecord | Record<string, unknown> | null | undefined): AskTarget | null {
  const poc = pocBlock(record)
  const provenance = obj(poc?.serving_provenance)
  const nonce = str(poc?.client_nonce)
  const other = poc?.role === 'served' ? str(provenance?.requested_by_node_id) : str(provenance?.served_by_node_id)
  const peerId = other?.toLowerCase() ?? null
  return peerId && FULL_ID.test(peerId) && nonce ? { peerId, nonce } : null
}

/** The row states whose record hasn't arrived, where asking can help. */
const ASKABLE_KINDS: ReadonlySet<RightCellStateKind> = new Set([
  'open_not_held',
  'open_not_given',
  'open_not_asked',
  'open_asked'
])

/** The ask is offered once the exchange is past the timeout, on a row still
 *  waiting for their record, when we know whom to ask and how. */
export function askIsOffered(
  kind: RightCellStateKind,
  target: AskTarget | null,
  timestamp: string | null,
  nowMs: number
): boolean {
  return ASKABLE_KINDS.has(kind) && target !== null && askForRecordIsDue(timestamp, nowMs)
}

function hexBytes(hex: string): Uint8Array | null {
  if (!/^([0-9a-f]{2})+$/i.test(hex)) return null
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return bytes
}

/** The bytes a refusal's signature covers: its three signed fields as JSON
 *  with sorted keys and no spaces (`capsule_emit.evidence_request.Refusal`). */
export function refusalSigningBody(refusal: { request_digest: string; reason: string; issued_at: string }): Uint8Array {
  const body = JSON.stringify({
    issued_at: refusal.issued_at,
    reason: refusal.reason,
    request_digest: refusal.request_digest
  })
  return new TextEncoder().encode(body)
}

/** The announced key's bytes, when the item names that same key. */
function announcedKeyBytes(namedKeyId: unknown, announcedKeyId: string | null): Uint8Array | null {
  const named = str(namedKeyId)?.toLowerCase()
  if (!announcedKeyId || named !== announcedKeyId.toLowerCase()) return null
  const key = hexBytes(announcedKeyId)
  return key && key.length === 32 ? key : null
}

/** Why a refusal proves nothing, or `null` when it holds: signed under the
 *  announced key, over OUR request. */
function refusalProblem(
  refusal: Record<string, unknown>,
  announcedKeyId: string | null,
  sentRequestDigest: string
): string | null {
  if (!announcedKeyId) return 'this node has no announced key for them, so their reply cannot be checked'
  const key = announcedKeyBytes(refusal.key_id, announcedKeyId)
  if (!key) return 'their reply is not signed with the key they announced'
  const requestDigest = str(refusal.request_digest)
  if (requestDigest?.toLowerCase() !== sentRequestDigest.toLowerCase()) {
    return 'their reply answers a different request'
  }
  const sig = hexBytes(str(refusal.sig) ?? '')
  const reason = str(refusal.reason)
  const issuedAt = str(refusal.issued_at)
  if (!sig || !reason || !issuedAt) return 'their reply is not signed with the key they announced'
  try {
    const body = refusalSigningBody({ request_digest: requestDigest, reason, issued_at: issuedAt })
    return ed25519.verify(sig, body, key) ? null : 'their reply is not signed with the key they announced'
  } catch {
    return 'their reply is not signed with the key they announced'
  }
}

/** A record's producer signature: a COSE_Sign1 over its own 32-byte
 *  `capsule_id`, under the key this node was told the peer signs with. A
 *  record naming any other key, or a peer with no announced key, fails. */
export function producerSignatureVerifies(record: Record<string, unknown>, announcedKeyId: string | null): boolean {
  const envelope = hexBytes(str(record.signature) ?? '')
  const key = announcedKeyBytes(record.key_id, announcedKeyId)
  const id = hexBytes(str(record.capsule_id) ?? '')
  if (!envelope || !key || !id) return false
  const result = verifyCoseSign1(envelope, key)
  return result.verified && result.payload.length === id.length && result.payload.every((b, i) => b === id[i])
}

export type AskJudges = {
  recomputeIdMatch: (record: Record<string, unknown>, capsuleId: string | null) => Promise<boolean | null>
  producerSignatureVerifies: (record: Record<string, unknown>, announcedKeyId: string | null) => boolean
}

const REAL_JUDGES: AskJudges = { recomputeIdMatch, producerSignatureVerifies }

/** Judge the other side's reply for the exchange whose request digest is
 *  `requestDigest`. */
export async function judgeAskReply(
  reply: EvidenceAskReply,
  requestDigest: string | null,
  askedAt: string,
  judges: AskJudges = REAL_JUDGES
): Promise<AskOutcome> {
  if (reply.kind === 'no_answer') return { kind: 'no_reply', at: askedAt, detail: reply.message }
  const answer = obj(reply.answer)
  if (answer && typeof answer.reason === 'string') {
    const problem = refusalProblem(answer, reply.announcedKeyId, reply.sentRequestDigest)
    if (problem) return { kind: 'no_reply', at: askedAt, detail: problem }
    const at = str(answer.issued_at) ?? askedAt
    if (answer.reason === COVERAGE_LAG) {
      return { kind: 'no_reply', at: askedAt, detail: 'they hold the record but cannot prove it yet; ask again later' }
    }
    return answer.reason === NO_SUCH_RECORD ? { kind: 'no_record', at } : { kind: 'refused', at, reason: answer.reason }
  }
  const receipts = (Array.isArray(answer?.bundles) ? answer.bundles : [])
    .map((bundle) => obj(obj(bundle)?.receipt))
    .filter((receipt): receipt is Record<string, unknown> => receipt !== null)
  const receipt =
    receipts.find((candidate) => obj(candidate.effect)?.request_digest === requestDigest) ?? receipts[0] ?? null
  if (!receipt) return { kind: 'no_reply', at: askedAt, detail: 'their reply carried no record' }
  const idMatch = await judges.recomputeIdMatch(receipt, str(receipt.capsule_id))
  return {
    kind: 'record',
    at: askedAt,
    evidence: {
      status: 'found',
      idMatch,
      signatureOk: judges.producerSignatureVerifies(receipt, reply.announcedKeyId),
      peerRecord: receipt,
      fetch: () => {}
    }
  }
}

/** The row's right cell once it has asked. */
export function stateAfterAsk(
  row: PaneCRow,
  outcome: AskOutcome,
  localRecord: CapsuleRecord | null | undefined
): RightCellState {
  switch (outcome.kind) {
    case 'asking':
    case 'no_reply':
      return { kind: 'open_asked', date: outcome.at }
    case 'refused':
      return { kind: 'open_refused', date: outcome.at }
    case 'no_record':
      return { kind: 'open_absent', date: outcome.at }
    case 'record':
      return deriveRightCellState(row, outcome.evidence, localRecord)
  }
}
