import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getUsers, getUser, updateUser } from '@/services/users'
import { toast, getErrorMessage } from '@/lib/toast'

/**
 * Fetch paginated user list.
 *
 * @param {{ page?: number, pageSize?: number }} params
 */
export function useUsers(params = {}) {
  return useQuery({
    queryKey: ['users', params],
    queryFn: () => getUsers(params),
  })
}

/**
 * Fetch a single user by ID.
 *
 * @param {number|string} userId
 * @param {{ enabled?: boolean }} options
 */
export function useUser(userId, { enabled = true } = {}) {
  return useQuery({
    queryKey: ['users', userId],
    queryFn: () => getUser(userId),
    enabled: !!userId && enabled,
  })
}

/**
 * Update a user's role or active status. Invalidates user queries on success.
 */
export function useUpdateUser() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ id, data }) => updateUser(id, data),
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      queryClient.invalidateQueries({ queryKey: ['users', variables.id] })
      toast.success('User updated')
    },
    onError: (error) => {
      toast.error('Failed to update user', { description: getErrorMessage(error) })
    },
  })
}
