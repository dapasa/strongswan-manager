import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  getUserPermissions,
  setUserPermissions,
  getAccessCatalog,
  createAccessRequest,
  getAccessRequests,
} from '@/services/permissions'
import { toast, getErrorMessage } from '@/lib/toast'

/** Fetch Tier 1 permissions for a specific user. */
export function useUserPermissions(userId, { enabled = true } = {}) {
  return useQuery({
    queryKey: ['user-permissions', userId],
    queryFn: () => getUserPermissions(userId),
    enabled: !!userId && enabled,
  })
}

/** Set the full Tier 1 permission list for a user (admin only). */
export function useSetUserPermissions() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ userId, permissions }) => setUserPermissions(userId, permissions),
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({ queryKey: ['user-permissions', variables.userId] })
      toast.success('Permissions saved')
    },
    onError: (error) => {
      toast.error('Failed to save permissions', { description: getErrorMessage(error) })
    },
  })
}

/** Fetch the Tier 2 access request catalog. */
export function useAccessCatalog() {
  return useQuery({
    queryKey: ['access-catalog'],
    queryFn: getAccessCatalog,
    staleTime: 5 * 60 * 1000, // 5 min — catalog rarely changes
  })
}

/** Submit a new Tier 2 access request. */
export function useCreateAccessRequest() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (payload) => createAccessRequest(payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['access-requests'] })
      toast.success('Access request submitted')
    },
    onError: (error) => {
      toast.error('Failed to submit request', { description: getErrorMessage(error) })
    },
  })
}

/** List access requests (all for admin, own for others). */
export function useAccessRequests() {
  return useQuery({
    queryKey: ['access-requests'],
    queryFn: getAccessRequests,
    refetchInterval: 30_000, // poll every 30 s — poller may grant/revoke
  })
}
