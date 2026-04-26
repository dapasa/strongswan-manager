import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getRules, createRule, updateRule, deleteRule, retryRule } from '@/services/iptables'
import { toast, getErrorMessage } from '@/lib/toast'

/**
 * Fetch iptables rules for a specific tunnel.
 *
 * @param {number|string} tunnelId
 * @param {{ enabled?: boolean }} options
 */
export function useIptablesRules(tunnelId, { enabled = true } = {}) {
  return useQuery({
    queryKey: ['tunnels', tunnelId, 'iptables-rules'],
    queryFn: () => getRules(tunnelId),
    enabled: !!tunnelId && enabled,
  })
}

/**
 * Create a new iptables rule on a tunnel.
 * Synchronous — returns the created rule directly.
 *
 * @param {number|string} tunnelId
 */
export function useCreateIptablesRule(tunnelId) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (ruleData) => createRule(tunnelId, ruleData),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tunnels', tunnelId, 'iptables-rules'] })
      toast.success('Rule created')
    },
    onError: (error) => {
      toast.error('Failed to create rule', { description: getErrorMessage(error) })
    },
  })
}

/**
 * Update an existing iptables rule.
 * Synchronous — returns the updated rule directly.
 *
 * @param {number|string} tunnelId
 */
export function useUpdateIptablesRule(tunnelId) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ ruleId, ruleData }) => updateRule(ruleId, ruleData),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tunnels', tunnelId, 'iptables-rules'] })
      toast.success('Rule updated')
    },
    onError: (error) => {
      toast.error('Failed to update rule', { description: getErrorMessage(error) })
    },
  })
}

/**
 * Delete an iptables rule.
 * Synchronous — returns 204 No Content.
 *
 * @param {number|string} tunnelId
 */
export function useDeleteIptablesRule(tunnelId) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (ruleId) => deleteRule(ruleId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tunnels', tunnelId, 'iptables-rules'] })
      toast.success('Rule deleted')
    },
    onError: (error) => {
      toast.error('Failed to delete rule', { description: getErrorMessage(error) })
    },
  })
}

/**
 * Retry a failed iptables rule sync.
 * Synchronous — returns the retried rule directly.
 *
 * @param {number|string} tunnelId
 */
export function useRetryIptablesRule(tunnelId) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (ruleId) => retryRule(ruleId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tunnels', tunnelId, 'iptables-rules'] })
      toast.info('Rule retry initiated')
    },
    onError: (error) => {
      toast.error('Failed to retry rule', { description: getErrorMessage(error) })
    },
  })
}
