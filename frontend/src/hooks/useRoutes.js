import { useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getRoutes, createRoute, deleteRoute, retryRoute } from '@/services/routes'
import { getOperation } from '@/services/operations'
import { toast, getErrorMessage } from '@/lib/toast'
import { POLL_INTERVAL, MAX_POLLS } from '@/lib/constants'

const IN_PROGRESS_STATUSES = new Set(['pending', 'pending_delete'])

/**
 * Fetch routes for a specific tunnel.
 * Auto-polls when any route is in an in-progress state.
 *
 * @param {number|string} tunnelId
 * @param {{ enabled?: boolean }} options
 */
export function useRoutes(tunnelId, { enabled = true } = {}) {
  return useQuery({
    queryKey: ['tunnels', tunnelId, 'routes'],
    queryFn: () => getRoutes(tunnelId),
    enabled: !!tunnelId && enabled,
    refetchInterval: (queryData) => {
      const routes = queryData.state.data
      if (!routes || !Array.isArray(routes)) return false
      const hasInProgress = routes.some((r) => IN_PROGRESS_STATUSES.has(r.sync_status))
      return hasInProgress ? POLL_INTERVAL : false
    },
  })
}

/**
 * Create a new route on a tunnel via the AWS EC2 API.
 * Returns the created RouteDetail (sync_status may be 'synced' or 'failed').
 *
 * @param {number|string} tunnelId
 */
export function useCreateRoute(tunnelId) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (routeData) => createRoute(tunnelId, routeData),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['tunnels', tunnelId, 'routes'] })
      if (data.sync_status === 'failed') {
        toast.warning('Route created with sync errors', {
          description: data.sync_error ?? undefined,
        })
      } else {
        toast.success('Route created')
      }
    },
    onError: (error) => {
      toast.error('Failed to create route', { description: getErrorMessage(error) })
    },
  })
}

/**
 * Delete a route and remove it from all AWS route tables.
 *
 * @param {number|string} tunnelId
 */
export function useDeleteRoute(tunnelId) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (routeId) => deleteRoute(routeId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tunnels', tunnelId, 'routes'] })
      toast.success('Route deleted')
    },
    onError: (error) => {
      toast.error('Failed to delete route', { description: getErrorMessage(error) })
    },
  })
}

/**
 * Retry a failed route — only retries the tables that did not succeed.
 *
 * @param {number|string} tunnelId
 */
export function useRetryRoute(tunnelId) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (routeId) => retryRoute(routeId),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['tunnels', tunnelId, 'routes'] })
      if (data.sync_status === 'failed') {
        toast.warning('Retry completed with errors')
      } else {
        toast.success('Route synced successfully')
      }
    },
    onError: (error) => {
      toast.error('Failed to retry route', { description: getErrorMessage(error) })
    },
  })
}

/**
 * Poll an async operation by ID. Uses refetchInterval to poll until terminal state.
 * Stops polling when status is 'completed' or 'failed', or after MAX_POLLS attempts.
 *
 * @param {string|null} operationId - UUID of the operation to poll
 * @param {{ enabled?: boolean, refetchInterval?: number }} options
 * @returns {{ ...queryResult, isTimedOut: boolean }}
 */
export function useOperation(operationId, { enabled = true, refetchInterval = POLL_INTERVAL } = {}) {
  const pollCountRef = useRef(0)
  const timedOutRef = useRef(false)

  // Reset counters when operationId changes
  const prevIdRef = useRef(operationId)
  if (prevIdRef.current !== operationId) {
    prevIdRef.current = operationId
    pollCountRef.current = 0
    timedOutRef.current = false
  }

  const query = useQuery({
    queryKey: ['operations', operationId],
    queryFn: () => {
      pollCountRef.current += 1
      return getOperation(operationId)
    },
    enabled: !!operationId && enabled,
    refetchInterval: (queryData) => {
      const status = queryData.state.data?.status
      if (status === 'completed' || status === 'failed') {
        return false
      }
      if (pollCountRef.current >= MAX_POLLS) {
        timedOutRef.current = true
        return false
      }
      return refetchInterval
    },
  })

  return {
    ...query,
    isTimedOut: timedOutRef.current,
  }
}
