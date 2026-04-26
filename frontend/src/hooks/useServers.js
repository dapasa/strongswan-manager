import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  getServers,
  getServer,
  createServer,
  updateServer,
  deleteServer,
  testServerConnection,
  checkServerStatus,
} from '@/services/servers'
import { toast, getErrorMessage } from '@/lib/toast'

/**
 * Fetch paginated server list.
 *
 * @param {{ page?: number, pageSize?: number, status?: string, search?: string }} params
 */
export function useServers(params = {}) {
  return useQuery({
    queryKey: ['servers', params],
    queryFn: () => getServers(params),
  })
}

/**
 * Fetch a single server by ID.
 *
 * @param {number|string} id
 * @param {{ enabled?: boolean }} options
 */
export function useServer(id, { enabled = true } = {}) {
  return useQuery({
    queryKey: ['servers', id],
    queryFn: () => getServer(id),
    enabled: !!id && enabled,
  })
}

/**
 * Create a new server. Invalidates server list on success.
 */
export function useCreateServer() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: createServer,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['servers'] })
      toast.success('Server created')
    },
    onError: (error) => {
      toast.error('Failed to create server', { description: getErrorMessage(error) })
    },
  })
}

/**
 * Update an existing server. Invalidates list and detail on success.
 */
export function useUpdateServer() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ id, data }) => updateServer(id, data),
    onSuccess: (data, variables) => {
      queryClient.invalidateQueries({ queryKey: ['servers'] })
      queryClient.invalidateQueries({ queryKey: ['servers', variables.id] })
      toast.success('Server updated')
    },
    onError: (error) => {
      toast.error('Failed to update server', { description: getErrorMessage(error) })
    },
  })
}

/**
 * Delete a server. Invalidates server list on success.
 */
export function useDeleteServer() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: deleteServer,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['servers'] })
      toast.success('Server deleted')
    },
    onError: (error) => {
      toast.error('Failed to delete server', { description: getErrorMessage(error) })
    },
  })
}

/**
 * Test SSH connection to a server. Invalidates server queries on success.
 */
export function useTestConnection() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: testServerConnection,
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['servers'] })
      if (data.success) {
        toast.success('Connection successful', { description: data.message })
      } else {
        toast.error('Connection failed', { description: data.message })
      }
    },
    onError: (error) => {
      toast.error('Failed to test connection', { description: getErrorMessage(error) })
    },
  })
}

/**
 * Check server status (reachable/unreachable). Invalidates server queries on success.
 */
export function useCheckStatus() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: checkServerStatus,
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['servers'] })
      queryClient.invalidateQueries({ queryKey: ['servers', data.server_id] })
      if (data.success) {
        toast.success('Server is reachable', { description: data.message })
      } else {
        toast.warning('Server is unreachable', { description: data.message })
      }
    },
    onError: (error) => {
      toast.error('Failed to check server status', { description: getErrorMessage(error) })
    },
  })
}
