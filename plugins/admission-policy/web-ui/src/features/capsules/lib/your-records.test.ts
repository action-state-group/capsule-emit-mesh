import { describe, expect, it } from 'vitest'
import { heroStatusLine } from '@/features/capsules/lib/your-records'

describe('hero line 3', () => {
  it('says the whole tab in one sentence, with the witness posture', () => {
    expect(heroStatusLine({ records: 8, confirmed: 3, disagreements: 0, witnessed: false })).toBe(
      '8 records · 3 confirmed by the other side · 0 disagreements · no outside witness (witness off — your choice)'
    )
    expect(heroStatusLine({ records: 1, confirmed: 0, disagreements: 1, witnessed: true })).toBe(
      '1 record · 0 confirmed by the other side · 1 disagreement · also held by a witness you don’t run'
    )
  })
})
