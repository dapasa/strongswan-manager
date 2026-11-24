import api from './api'

export async function getTunnels({ page = 1, pageSize = 20, status, syncStatus, search } = {}) {
  const { data } = await api.get('/tunnels/', {
    params: {
      page,
      page_size: pageSize,
      status,
      sync_status: syncStatus,
      search,
    },
  })
  return data
}

export async function getTunnel(tunnelId) {
  const { data } = await api.get(`/tunnels/${tunnelId}`)
  return data
}

export async function createTunnel(tunnelData) {
  const { data } = await api.post('/tunnels/', tunnelData)
  return data
}

export async function updateTunnel(tunnelId, tunnelData) {
  const { data } = await api.patch(`/tunnels/${tunnelId}`, tunnelData)
  return data
}

export async function deleteTunnel(tunnelId) {
  const { data } = await api.delete(`/tunnels/${tunnelId}`)
  return data
}

export async function getTunnelStatus(tunnelId) {
  const { data } = await api.get(`/tunnels/${tunnelId}/status`)
  return data
}

export async function retryTunnelSync(tunnelId) {
  const { data } = await api.post(`/tunnels/${tunnelId}/retry`)
  return data
}

export async function checkTunnelStatus(tunnelId) {
  const { data } = await api.post(`/tunnels/${tunnelId}/check-status`)
  return data
}

export async function getAllTunnelsLiveStatus() {
  const { data } = await api.get('/tunnels/status/live')
  return data
}

export async function rotateTunnelPsk(tunnelId, psk) {
  const { data } = await api.post(
    `/tunnels/${tunnelId}/rotate-psk`,
    psk != null ? { psk } : {}
  )
  return data
}

export async function initiateTunnel(tunnelId) {
  const { data } = await api.post(`/tunnels/${tunnelId}/initiate`)
  return data
}

export async function terminateTunnel(tunnelId) {
  const { data } = await api.post(`/tunnels/${tunnelId}/terminate`)
  return data
}
