import api from './api'

/** GET /users/{userId}/permissions — returns { user_id, permissions: string[] } */
export async function getUserPermissions(userId) {
  const { data } = await api.get(`/users/${userId}/permissions`)
  return data
}

/** PUT /users/{userId}/permissions — sets the full Tier 1 permission set */
export async function setUserPermissions(userId, permissions) {
  const { data } = await api.put(`/users/${userId}/permissions`, { permissions })
  return data
}

/** GET /access-requests/catalog — returns { entries, enabled } */
export async function getAccessCatalog() {
  const { data } = await api.get('/access-requests/catalog')
  return data
}

/** POST /access-requests/ — create a new Tier 2 access request */
export async function createAccessRequest(payload) {
  const { data } = await api.post('/access-requests/', payload)
  return data
}

/** GET /access-requests/ — list requests (all requests for admin, own for others) */
export async function getAccessRequests() {
  const { data } = await api.get('/access-requests/')
  return data
}
