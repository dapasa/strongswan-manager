import api from './api'

export async function getDashboardSummary() {
  const { data } = await api.get('/dashboard/summary')
  return data
}

export async function getRecentActivity() {
  const { data } = await api.get('/dashboard/recent-activity')
  return data
}

export async function getReconcilerStatus() {
  const { data } = await api.get('/reconciler/status')
  return data
}
