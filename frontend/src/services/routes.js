import api from './api'

export async function getRoutes(tunnelId) {
  const { data } = await api.get(`/tunnels/${tunnelId}/routes`)
  return data
}

export async function createRoute(tunnelId, { cidr, description }) {
  const { data } = await api.post('/routes/', { cidr, description }, {
    params: { tunnel_id: tunnelId },
  })
  return data
}

export async function deleteRoute(routeId) {
  await api.delete(`/routes/${routeId}`)
}

export async function retryRoute(routeId) {
  const { data } = await api.post(`/routes/${routeId}/retry`)
  return data
}
