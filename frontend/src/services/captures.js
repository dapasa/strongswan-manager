import { api } from './api'

export const capturesService = {
  async list(params = {}) {
    const q = new URLSearchParams()
    if (params.server_id) q.set('server_id', params.server_id)
    if (params.limit) q.set('limit', params.limit)
    const qs = q.toString() ? `?${q}` : ''
    const res = await api.get(`/api/v1/captures${qs}`)
    return res.data
  },

  async start(data) {
    const res = await api.post('/api/v1/captures', data)
    return res.data
  },

  async readOutput(captureId) {
    const res = await api.get(`/api/v1/captures/${captureId}/output`)
    return res.data
  },

  async delete(captureId) {
    await api.delete(`/api/v1/captures/${captureId}`)
  },
}
