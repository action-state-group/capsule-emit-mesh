// The Ledger's exchange_id column cell: the short id
// plus an "open in Logs" affordance, split into its own file so the column
// definitions module (`ExchangeColumns.tsx`) stays a components-only export
// boundary for fast refresh.
import { ArrowUpRight } from 'lucide-react'
import { navigateHost } from '@/plugin-host/host'

/** A digest-keyed grouping fallback (`exchange_key_for`, host side) is not a
 *  real exchange join-key -- `open in Logs` must never link on one, since no
 *  Logs row can ever carry a `digest:` value as its `exchangeId`. */
function isRealExchangeId(exchangeKey: string): boolean {
  return !exchangeKey.startsWith('digest:')
}

export function ExchangeIdCell({ exchangeKey }: { exchangeKey: string }) {
  return (
    <span className="flex items-center gap-1.5">
      <span className="font-mono text-foreground" title={exchangeKey}>
        {exchangeKey.slice(0, 8)}
      </span>
      {isRealExchangeId(exchangeKey) ? (
        <button
          aria-label={`Open exchange ${exchangeKey} in Logs`}
          className="ui-control-ghost rounded-[var(--radius)] p-0.5 text-fg-dim hover:text-foreground"
          onClick={(event) => {
            event.stopPropagation()
            navigateHost(`/logs?focusExchangeId=${encodeURIComponent(exchangeKey)}`)
          }}
          type="button"
        >
          <ArrowUpRight aria-hidden="true" className="size-3" />
        </button>
      ) : null}
    </span>
  )
}
