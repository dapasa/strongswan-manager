import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip'
import StatusBadge from '@/components/shared/StatusBadge'

/**
 * Displays the live IPsec state for a single tunnel row.
 * Data comes from the parent (bulk live-status query) — no per-row fetch.
 *
 * @param {{
 *   liveRow?: { overall: string, per_server: Array<{ server_id: number, server_name: string, state: string, success: boolean, error?: string }> },
 *   isLoading?: boolean,
 *   isError?: boolean,
 * }} props
 */
export default function TunnelStatusCell({ liveRow, isLoading, isError }) {
  if (isLoading) return <StatusBadge status="LOADING" />
  if (isError || !liveRow) return <StatusBadge status="UNKNOWN" />

  const overall = liveRow.overall ?? 'UNKNOWN'
  const perServer = liveRow.per_server ?? []

  if (perServer.length === 0) {
    return <StatusBadge status={overall} />
  }

  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          <span className="cursor-default">
            <StatusBadge status={overall} />
          </span>
        </TooltipTrigger>
        <TooltipContent>
          <div className="space-y-1">
            {perServer.map((s) => (
              <div key={s.server_id} className="flex items-center gap-2 text-xs">
                <span className="font-mono">{s.server_name}:</span>
                <span
                  className={
                    s.state === 'UP'
                      ? 'text-emerald-300'
                      : s.state === 'DOWN'
                        ? 'text-red-300'
                        : 'text-gray-300'
                  }
                >
                  {s.state}
                </span>
                {s.error && (
                  <span className="text-yellow-300 truncate max-w-[160px]" title={s.error}>
                    {s.error}
                  </span>
                )}
              </div>
            ))}
          </div>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  )
}
