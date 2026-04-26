import api from './api'

export async function getAuditLogs({ page = 1, pageSize = 50, userId, entityType, action, dateFrom, dateTo } = {}) {
  const { data } = await api.get('/audit/', {
    params: {
      page,
      page_size: pageSize,
      user_id: userId,
      entity_type: entityType,
      action,
      date_from: dateFrom,
      date_to: dateTo,
    },
  })
  return data
}
