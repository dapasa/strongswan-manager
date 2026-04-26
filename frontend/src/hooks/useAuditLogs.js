import { useQuery } from '@tanstack/react-query'
import { getAuditLogs } from '@/services/audit'

/**
 * Fetch paginated, filterable audit logs.
 *
 * The filters object is included in the query key so TanStack Query
 * automatically refetches when any filter value changes.
 *
 * @param {{ page?: number, pageSize?: number, dateFrom?: string, dateTo?: string, userId?: string, entityType?: string, action?: string }} filters
 */
export function useAuditLogs(filters = {}) {
  const { page = 1, pageSize = 50, dateFrom, dateTo, userId, entityType, action } = filters

  return useQuery({
    queryKey: ['audit-logs', { page, pageSize, dateFrom, dateTo, userId, entityType, action }],
    queryFn: () =>
      getAuditLogs({
        page,
        pageSize,
        dateFrom: dateFrom || undefined,
        dateTo: dateTo || undefined,
        userId: userId || undefined,
        entityType: entityType || undefined,
        action: action || undefined,
      }),
    keepPreviousData: true,
  })
}
