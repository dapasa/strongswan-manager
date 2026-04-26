import api from './api'

export async function getRoutes(tunnelId) {
  const { data } = await api.get(`/tunnels/${tunnelId}/routes`)
  return data
}

export async function createRoute(tunnelId, routeData) {
  const { data } = await api.post(`/tunnels/${tunnelId}/routes`, routeData)
  return data
}

export async function deleteRoute(routeId) {
  const { data } = await api.delete(`/routes/${routeId}`)
  return data
}

export async function retryRoute(routeId) {
  const { data } = await api.post(`/routes/${routeId}/retry`)
  return data
}
