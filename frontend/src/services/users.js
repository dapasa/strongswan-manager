import api from './api'

export async function getUsers({ page = 1, pageSize = 50 } = {}) {
  const { data } = await api.get('/users/', {
    params: { page, page_size: pageSize },
  })
  return data
}

export async function getUser(userId) {
  const { data } = await api.get(`/users/${userId}`)
  return data
}

export async function updateUser(userId, userData) {
  const { data } = await api.patch(`/users/${userId}`, userData)
  return data
}
