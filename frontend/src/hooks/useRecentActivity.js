import { useQuery } from '@tanstack/react-query'
import { getAuditLogs } from '@/services/audit'
import { DASHBOARD_REFETCH_INTERVAL } from '@/lib/constants'

/**
 * Fetch the 5 most recent audit log entries for the dashboard.
 *
 * The audit endpoint already sorts by created_at DESC, so page=1 & pageSize=5
 * gives us the latest entries.
 *
 * @param {{ refetchInterval?: number }} options
 */
export function useRecentActivity({ refetchInterval = DASHBOARD_REFETCH_INTERVAL } = {}) {
  const query = useQuery({
    queryKey: ['audit-logs', 'recent'],
    queryFn: () => getAuditLogs({ page: 1, pageSize: 5 }),
    refetchInterval,
  })

  return {
    ...query,
    /** Convenience — unwrap paginated response to just the items list */
    data: query.data?.items ?? [],
  }
}
