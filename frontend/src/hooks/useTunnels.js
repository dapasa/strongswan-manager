import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  getTunnels,
  getTunnel,
  createTunnel,
  updateTunnel,
  deleteTunnel,
  getTunnelStatus,
  retryTunnelSync,
  checkTunnelStatus,
  getAllTunnelsLiveStatus,
  rotateTunnelPsk,
  initiateTunnel,
  terminateTunnel,
} from '@/services/tunnels'
import { toast, getErrorMessage } from '@/lib/toast'

/**
 * Fetch paginated tunnel list.
 *
 * @param {{ page?: number, pageSize?: number, status?: string, syncStatus?: string, search?: string }} params
 */
export function useTunnels(params = {}) {
  return useQuery({
    queryKey: ['tunnels', params],
    queryFn: () => getTunnels(params),
  })
}

/**
 * Fetch a single tunnel by ID.
 *
 * @param {number|string} id
 * @param {{ enabled?: boolean }} options
 */
export function useTunnel(id, { enabled = true } = {}) {
  return useQuery({
    queryKey: ['tunnels', id],
    queryFn: () => getTunnel(id),
    enabled: !!id && enabled,
  })
}

/**
 * Create a new tunnel. Invalidates tunnel list on success.
 */
export function useCreateTunnel() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: createTunnel,
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['tunnels'] })
      if (data.sync_status === 'failed') {
        toast.warning('Tunnel created but sync failed', { description: data.sync_error })
      } else {
        toast.success('Tunnel created and synced')
      }
    },
    onError: (error) => {
      // 422 field validation errors are shown inline by TunnelForm; skip toast.
      if (error?.response?.status === 422 && Array.isArray(error?.response?.data?.detail)) return
      toast.error('Failed to create tunnel', { description: getErrorMessage(error) })
    },
  })
}

/**
 * Update an existing tunnel. Invalidates list and detail on success.
 */
export function useUpdateTunnel() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ id, data }) => updateTunnel(id, data),
    onSuccess: (data, variables) => {
      queryClient.invalidateQueries({ queryKey: ['tunnels'] })
      queryClient.invalidateQueries({ queryKey: ['tunnels', variables.id] })
      if (data.sync_status === 'failed') {
        toast.warning('Tunnel updated but sync failed', { description: data.sync_error })
      } else {
        toast.success('Tunnel updated and synced')
      }
    },
    onError: (error) => {
      // 422 field validation errors are shown inline by TunnelForm; skip toast.
      if (error?.response?.status === 422 && Array.isArray(error?.response?.data?.detail)) return
      toast.error('Failed to update tunnel', { description: getErrorMessage(error) })
    },
  })
}

/**
 * Delete a tunnel. Invalidates tunnel list on success.
 */
export function useDeleteTunnel() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: deleteTunnel,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tunnels'] })
      toast.success('Tunnel deleted')
    },
    onError: (error) => {
      toast.error('Failed to delete tunnel', { description: getErrorMessage(error) })
    },
  })
}

/**
 * Retry a failed tunnel sync. Invalidates tunnel queries on success.
 */
export function useRetryTunnelSync() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: retryTunnelSync,
    onSuccess: (data, tunnelId) => {
      queryClient.invalidateQueries({ queryKey: ['tunnels'] })
      queryClient.invalidateQueries({ queryKey: ['tunnels', tunnelId] })
      if (data.sync_status === 'synced') {
        toast.success('Tunnel synced successfully')
      } else {
        toast.error('Sync failed', { description: data.sync_error || 'Unknown error during sync' })
      }
    },
    onError: (error) => {
      toast.error('Failed to retry tunnel sync', { description: getErrorMessage(error) })
    },
  })
}

/**
 * Fetch live tunnel status from strongSwan.
 *
 * @param {number|string} id
 * @param {{ enabled?: boolean, refetchInterval?: number|false }} options
 */
export function useTunnelStatus(id, { enabled = true, refetchInterval = false } = {}) {
  return useQuery({
    queryKey: ['tunnels', id, 'status'],
    queryFn: () => getTunnelStatus(id),
    enabled: !!id && enabled,
    refetchInterval,
  })
}

/**
 * Fetch live status of ALL tunnels in one SSM fan-out call.
 * Returns { tunnels, summary, checked_at, server_errors }.
 * Slow (seconds) — do not use to block the tunnel list render.
 *
 * @param {{ refetchInterval?: number }} options
 */
export function useAllTunnelsLiveStatus({ refetchInterval = 30_000 } = {}) {
  return useQuery({
    queryKey: ['tunnels', 'status', 'live'],
    queryFn: getAllTunnelsLiveStatus,
    refetchInterval,
  })
}

/**
 * Rotate the PSK for a tunnel. Pushes to all VPN nodes.
 * Returns the new PSK once — the caller must surface it in a dialog and clear it on close.
 * Invalidates tunnel queries on success; never toasts the PSK.
 */
export function useRotateTunnelPsk() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ tunnelId, psk }) => rotateTunnelPsk(tunnelId, psk),
    onSuccess: (data, variables) => {
      queryClient.invalidateQueries({ queryKey: ['tunnels'] })
      queryClient.invalidateQueries({ queryKey: ['tunnels', variables.tunnelId] })
    },
    onError: (error) => {
      toast.error('Failed to rotate PSK', { description: getErrorMessage(error) })
    },
  })
}

/**
 * Bring a tunnel up (initiate) via swanctl on the VPN node.
 * Returns { tunnel_id, action, node, instance_id, success, output }.
 * success=false means swanctl ran but reported failure — shown as an error toast.
 * Invalidates the live-status query so the Status badge refreshes.
 */
export function useInitiateTunnel() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: initiateTunnel,
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['tunnels', 'status', 'live'] })
      if (data.success) {
        toast.success(`Tunnel brought up on ${data.node}`)
      } else {
        const out = data.output ?? 'Unknown error'
        toast.error('Bring up failed', {
          description: out.length > 200 ? out.slice(0, 200) + '…' : out,
        })
      }
    },
    onError: (error) => {
      toast.error('Failed to bring up tunnel', { description: getErrorMessage(error) })
    },
  })
}

/**
 * Bring a tunnel down (terminate) via swanctl on the VPN node.
 * Returns { tunnel_id, action, node, instance_id, success, output }.
 * success=false means swanctl ran but reported failure — shown as an error toast.
 * Invalidates the live-status query so the Status badge refreshes.
 */
export function useTerminateTunnel() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: terminateTunnel,
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['tunnels', 'status', 'live'] })
      if (data.success) {
        toast.success(`Tunnel brought down on ${data.node}`)
      } else {
        const out = data.output ?? 'Unknown error'
        toast.error('Bring down failed', {
          description: out.length > 200 ? out.slice(0, 200) + '…' : out,
        })
      }
    },
    onError: (error) => {
      toast.error('Failed to bring down tunnel', { description: getErrorMessage(error) })
    },
  })
}

/**
 * Check operational tunnel status on demand via SSM.
 * Runs `ipsec status <name>` and updates the DB status field.
 */
export function useCheckTunnelStatus() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: checkTunnelStatus,
    onSuccess: (data, tunnelId) => {
      queryClient.invalidateQueries({ queryKey: ['tunnels', tunnelId] })
      queryClient.invalidateQueries({ queryKey: ['tunnels', tunnelId, 'status'] })
      const stateLabel = data.state === 'UP' ? 'UP' : data.state === 'DOWN' ? 'DOWN' : 'UNKNOWN'
      if (data.state === 'UP') {
        toast.success(`Tunnel is ${stateLabel}`)
      } else if (data.state === 'DOWN') {
        toast.warning(`Tunnel is ${stateLabel}`, { description: 'IPsec connection is not established' })
      } else {
        toast.info(`Tunnel status: ${stateLabel}`, { description: 'Could not determine tunnel state' })
      }
    },
    onError: (error) => {
      toast.error('Failed to check tunnel status', { description: getErrorMessage(error) })
    },
  })
}
