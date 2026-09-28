import { describe, expect, it } from 'vitest'
import { doorNotice } from '@/features/capsules/lib/door-status'

describe('doorNotice', () => {
  it('says plainly when the door is not running, naming its address', () => {
    expect(doorNotice({ state: 'not_running', url: 'http://127.0.0.1:8091' })).toMatch(
      /^Confirmation unavailable: the evidence door isn't running at http:\/\/127\.0\.0\.1:8091/
    )
  })

  it('says when the door failed authentication', () => {
    expect(doorNotice({ state: 'auth_failed', url: 'http://127.0.0.1:8091' })).toMatch(/failed authentication/)
  })

  it('shows nothing when the door is ready, or when there is no answer yet', () => {
    expect(doorNotice({ state: 'ready', url: 'x' })).toBeNull()
    expect(doorNotice({ state: 'unknown', url: 'x' })).toBeNull()
    expect(doorNotice(null)).toBeNull()
  })
})
