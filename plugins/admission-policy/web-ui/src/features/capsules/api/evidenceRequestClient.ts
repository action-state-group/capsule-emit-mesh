// Ask the other side of an exchange for its record: this plugin's
// `mesh_evidence_request` tool (`tools/mesh_evidence_request`) sends one
// evidence request to that node over the mesh and hands back its reply
// unchanged -- an artifact carrying the record, or the refusal it signed.
// The key the reply is judged under comes from this plugin's `peer-key` route
// (the operator's `ADMISSION_POLICY_PEER_KEYS`), never from the reply. This
// client carries bytes; `ask-for-record.ts` judges them.
//
// Ported from the fork console, which reached the same tool through a host
// route (`POST /api/evidence-requests`) that also looked up the key.
import { sha256Hex } from '@/features/capsules/lib/canonical'
import { getPluginJson, pluginHost } from '@/plugin-host/host'

export const EVIDENCE_REQUEST_ROUTE = 'tools/mesh_evidence_request'
export const peerKeyRoute = (peerId: string) => `http/peer-key?peer=${encodeURIComponent(peerId)}`

/** An answer comes with what it must be judged against: the key this node
 *  was told the peer signs with (`null` when none is announced), and the
 *  digest of the request bytes we sent, which a refusal must name. */
export type EvidenceAskReply =
  | { kind: 'answer'; answer: unknown; announcedKeyId: string | null; sentRequestDigest: string }
  | { kind: 'no_answer'; message: string }

/** The evidence request that names one exchange by the client nonce both
 *  records of it carry. Keys sorted at every level, so the bytes the peer
 *  digests are these whether the hops on the way keep key order or sort it
 *  (`serde_json` does one or the other, compact either way). */
export function askByNonceRequest(nonce: string): Record<string, unknown> {
  return { coverage: {}, subject: { by: 'nonce', kind: 'correlation', value: nonce } }
}

/** The bytes the peer receives for `request`: compact JSON. */
export function evidenceRequestBytes(request: Record<string, unknown>): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(request))
}

/** The key this node was told `peerId` signs with, or `null` when none is
 *  announced or the route can't say: an unknown key is never a guess. */
async function announcedKeyFor(peerId: string): Promise<string | null> {
  try {
    const body = await getPluginJson<{ announced_key_id?: unknown }>(peerKeyRoute(peerId))
    return typeof body.announced_key_id === 'string' ? body.announced_key_id.toLowerCase() : null
  } catch {
    return null
  }
}

export async function askForRecord(peerId: string, nonce: string): Promise<EvidenceAskReply> {
  const request = askByNonceRequest(nonce)
  const sentRequestDigest = await sha256Hex(evidenceRequestBytes(request))
  let response: Response
  try {
    response = await pluginHost().network.fetchPlugin(EVIDENCE_REQUEST_ROUTE, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ peer_id: peerId, request })
    })
  } catch (error) {
    return { kind: 'no_answer', message: error instanceof Error ? error.message : 'network error' }
  }
  if (!response.ok) {
    const text = await response.text().catch(() => '')
    return { kind: 'no_answer', message: text || `HTTP ${response.status}` }
  }
  // The tool answers with the peer's reply itself, unwrapped.
  let answer: unknown
  try {
    answer = await response.json()
  } catch {
    return { kind: 'no_answer', message: 'the reply was not JSON' }
  }
  if (answer === null || typeof answer !== 'object')
    return { kind: 'no_answer', message: 'the reply carried no answer' }
  return { kind: 'answer', answer, announcedKeyId: await announcedKeyFor(peerId), sentRequestDigest }
}
