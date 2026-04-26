import api from './api'

export async function getOperation(operationId) {
  const { data } = await api.get(`/operations/${operationId}`)
  return data
}

/**
 * Poll an async operation until it reaches a terminal state.
 * Primarily used via useAsyncOperation hook, but available for direct use.
 */
export async function pollOperation(operationId, { interval = 3000, maxPolls = 100 } = {}) {
  let polls = 0
  while (polls < maxPolls) {
    const data = await getOperation(operationId)
    if (data.status === 'completed' || data.status === 'failed') {
      return data
    }
    polls += 1
    await new Promise((resolve) => setTimeout(resolve, interval))
  }
  throw new Error(`Operation ${operationId} timed out after ${maxPolls} polls`)
}
