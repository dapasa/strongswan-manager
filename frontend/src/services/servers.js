import api from './api'

export async function getServers({ page = 1, pageSize = 20, status, search } = {}) {
  const { data } = await api.get('/servers/', {
    params: {
      page,
      page_size: pageSize,
      status_filter: status,
      search,
    },
  })
  return data
}

export async function getServer(serverId) {
  const { data } = await api.get(`/servers/${serverId}`)
  return data
}

export async function createServer(serverData) {
  const { data } = await api.post('/servers/', serverData)
  return data
}

export async function updateServer(serverId, serverData) {
  const { data } = await api.patch(`/servers/${serverId}`, serverData)
  return data
}

export async function deleteServer(serverId) {
  const { data } = await api.delete(`/servers/${serverId}`)
  return data
}

export async function testServerConnection(serverId) {
  const { data } = await api.post(`/servers/${serverId}/test`)
  return data
}

export async function checkServerStatus(serverId) {
  const { data } = await api.post(`/servers/${serverId}/status`)
  return data
}
