// The evidence door's state, as the plugin's `http/door` route reports it,
// and the page's one-line notice for it. The door receives the other side's
// records and answers requests for ours; without it, no exchange can reach
// CLOSED on this node, and the page says so instead of staying silent.

export type DoorState = 'ready' | 'not_running' | 'auth_failed' | 'unknown'

export type DoorStatus = { state: DoorState; url: string }

export const DOOR_ROUTE = 'http/door'

/** The notice for a door that is not usable, or null when it is ready (or
 *  when this view has no answer: never a warning it did not check). */
export function doorNotice(status: DoorStatus | null | undefined): string | null {
  if (!status) return null
  switch (status.state) {
    case 'not_running':
      return `Confirmation unavailable: the evidence door isn't running at ${status.url}. The other side's records can't reach this node, and requests for yours are not answered.`
    case 'auth_failed':
      return `Confirmation unavailable: the evidence door at ${status.url} failed authentication (it does not hold this install's token). Its replies are ignored.`
    default:
      return null
  }
}
