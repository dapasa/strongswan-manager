import api from './api'

/**
 * Fetch iptables rules for a tunnel.
 * Backend: GET /api/v1/iptables/?tunnel_id={tunnelId}
 */
export async function getRules(tunnelId) {
  const { data } = await api.get('/iptables/', {
    params: { tunnel_id: tunnelId },
  })
  return data
}

/**
 * Create a new iptables rule for a tunnel.
 * Backend: POST /api/v1/iptables/?tunnel_id={tunnelId}
 */
export async function createRule(tunnelId, ruleData) {
  const { data } = await api.post('/iptables/', ruleData, {
    params: { tunnel_id: tunnelId },
  })
  return data
}

/**
 * Update an iptables rule.
 * Backend: PATCH /api/v1/iptables/{ruleId}
 */
export async function updateRule(ruleId, ruleData) {
  const { data } = await api.patch(`/iptables/${ruleId}`, ruleData)
  return data
}

/**
 * Delete an iptables rule.
 * Backend: DELETE /api/v1/iptables/{ruleId}
 */
export async function deleteRule(ruleId) {
  const { data } = await api.delete(`/iptables/${ruleId}`)
  return data
}

/**
 * Retry a failed iptables rule sync.
 * Backend: POST /api/v1/iptables/{ruleId}/retry
 */
export async function retryRule(ruleId) {
  const { data } = await api.post(`/iptables/${ruleId}/retry`)
  return data
}
