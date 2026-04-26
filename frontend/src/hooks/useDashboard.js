import { useQuery } from '@tanstack/react-query'
import { getDashboardSummary } from '@/services/dashboard'
import { DASHBOARD_REFETCH_INTERVAL } from '@/lib/constants'

/**
 * Fetch dashboard summary metrics with auto-refresh.
 *
 * @param {{ refetchInterval?: number }} options
 * @returns {{ data: object, isLoading: boolean, isError: boolean, error: Error|null, refetch: Function }}
 */
export function useDashboard({ refetchInterval = DASHBOARD_REFETCH_INTERVAL } = {}) {
  return useQuery({
    queryKey: ['dashboard', 'summary'],
    queryFn: getDashboardSummary,
    refetchInterval,
  })
}
