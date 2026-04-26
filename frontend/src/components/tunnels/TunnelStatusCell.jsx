import { POLL_INTERVAL } from '@/lib/constants'
import { useTunnelStatus } from '@/hooks/useTunnels'
import StatusBadge from '@/components/shared/StatusBadge'

/**
 * Fetches and displays live tunnel status in a table cell.
 * Polls at the configured interval.
 *
 * @param {{ tunnelId: number }} props
 */
export default function TunnelStatusCell({ tunnelId }) {
  const { data, isLoading, isError } = useTunnelStatus(tunnelId, {
    refetchInterval: POLL_INTERVAL,
  })

  if (isLoading) {
    return <StatusBadge status="LOADING" />
  }

  if (isError) {
    return <StatusBadge status="UNKNOWN" />
  }

  return <StatusBadge status={data?.state ?? 'UNKNOWN'} />
}
