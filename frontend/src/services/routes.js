import api from './api'

export async function getRoutes(tunnelId) {
  const { data } = await api.get(`/tunnels/${tunnelId}/routes`)
  return data
}
