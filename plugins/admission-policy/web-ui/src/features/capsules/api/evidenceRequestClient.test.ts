import { afterEach, describe, expect, it, vi } from 'vitest'
import { askByNonceRequest, askForRecord, evidenceRequestBytes } from '@/features/capsules/api/evidenceRequestClient'
import { sha256Hex } from '@/features/capsules/lib/canonical'

afterEach(() => {
  vi.unstubAllGlobals()
})

const PEER = 'c'.repeat(64)

/** The tool answers the peer's reply; `peer-key` answers the announced key. */
function stubRoutes(answer: unknown, announced: unknown, askStatus = 200) {
  const fetchMock = vi.fn(async (url: string | URL) =>
    String(url).includes('/http/peer-key')
      ? new Response(JSON.stringify({ announced_key_id: announced }))
      : new Response(JSON.stringify(answer), { status: askStatus })
  )
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

describe('askForRecord', () => {
  it("posts to this plugin's tool and names the digest of the exact request bytes it sent, and the announced key", async () => {
    const fetchMock = stubRoutes({ reason: 'no_such_record' }, 'AB'.repeat(32))

    const reply = await askForRecord(PEER, 'nonce-1')

    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit]
    expect(String(url)).toBe('/api/plugins/capsule-emit-mesh/tools/mesh_evidence_request')
    expect(init.method).toBe('POST')
    const sent = JSON.parse(String(init.body)) as { peer_id: string; request: Record<string, unknown> }
    expect(sent.peer_id).toBe(PEER)
    // The peer digests these bytes (compact, keys sorted, as serde_json
    // re-serializes them either way); a refusal must name this digest.
    expect(JSON.stringify(sent.request)).toBe(
      '{"coverage":{},"subject":{"by":"nonce","kind":"correlation","value":"nonce-1"}}'
    )
    expect(String(fetchMock.mock.calls[1][0])).toBe(`/api/plugins/capsule-emit-mesh/http/peer-key?peer=${PEER}`)
    expect(reply).toEqual({
      kind: 'answer',
      answer: { reason: 'no_such_record' },
      announcedKeyId: 'ab'.repeat(32),
      sentRequestDigest: await sha256Hex(evidenceRequestBytes(askByNonceRequest('nonce-1')))
    })
  })

  it('carries no announced key when the plugin has none for that peer', async () => {
    stubRoutes({}, null)
    const reply = await askForRecord(PEER, 'nonce-1')
    expect(reply).toMatchObject({ kind: 'answer', announcedKeyId: null })
  })

  it('a tool error is no answer, never an answer', async () => {
    stubRoutes('could not reach peer', null, 502)
    expect(await askForRecord(PEER, 'nonce-1')).toMatchObject({ kind: 'no_answer' })
  })
})
