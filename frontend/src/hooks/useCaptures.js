import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { capturesService } from '@/services/captures'
import { toast } from '@/lib/toast'

export function useCaptures(params = {}) {
  return useQuery({
    queryKey: ['captures', params],
    queryFn: () => capturesService.list(params),
  })
}

export function useStartCapture() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data) => capturesService.start(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['captures'] })
      toast.success('Capture started successfully')
    },
    onError: (err) => {
      toast.error(err?.response?.data?.detail || 'Failed to start capture')
    },
  })
}

/** Poll a single capture until it leaves the 'running' state (every 3 s). */
export function useCapture(captureId, { enabled = true } = {}) {
  return useQuery({
    queryKey: ['capture', captureId],
    queryFn: () => capturesService.getOne(captureId),
    enabled: enabled && !!captureId,
    refetchInterval: (query) => {
      const data = query.state.data
      return data?.status === 'running' ? 3000 : false
    },
  })
}

export function useCaptureOutput(captureId, { enabled = true } = {}) {
  return useQuery({
    queryKey: ['capture-output', captureId],
    queryFn: () => capturesService.readOutput(captureId),
    enabled: enabled && !!captureId,
  })
}

export function useDeleteCapture() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (captureId) => capturesService.delete(captureId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['captures'] })
      toast.success('Capture deleted')
    },
    onError: (err) => {
      toast.error(err?.response?.data?.detail || 'Failed to delete capture')
    },
  })
}
