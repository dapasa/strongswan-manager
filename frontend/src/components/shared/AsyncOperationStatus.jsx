import { useEffect, useRef } from 'react'
import { Loader2, CheckCircle2, XCircle, Clock } from 'lucide-react'
import { cn } from '@/lib/utils'
import { useOperation } from '@/hooks/useRoutes'

const statusConfig = {
  pending: {
    icon: Clock,
    label: 'Pending',
    color: 'text-muted-foreground',
    spin: false,
  },
  running: {
    icon: Loader2,
    label: 'In progress',
    color: 'text-blue-500',
    spin: true,
  },
  completed: {
    icon: CheckCircle2,
    label: 'Completed',
    color: 'text-emerald-500',
    spin: false,
  },
  failed: {
    icon: XCircle,
    label: 'Failed',
    color: 'text-destructive',
    spin: false,
  },
}

/**
 * Displays async operation progress by polling the operation endpoint.
 * Reusable for routes, iptables, or any async operation.
 *
 * @param {{
 *   operationId: string|null,
 *   onCompleted?: (data: object) => void,
 *   onFailed?: (data: object) => void,
 *   className?: string,
 * }} props
 */
export default function AsyncOperationStatus({ operationId, onCompleted, onFailed, className }) {
  const operation = useOperation(operationId, {
    enabled: !!operationId,
  })
  const calledRef = useRef(null)

  const status = operation.data?.status

  useEffect(() => {
    if (!status || calledRef.current === operationId) return
    if (status === 'completed') {
      calledRef.current = operationId
      onCompleted?.(operation.data)
    } else if (status === 'failed') {
      calledRef.current = operationId
      onFailed?.(operation.data)
    }
  }, [status, operationId, onCompleted, onFailed, operation.data])

  if (!operationId || !operation.data) {
    return null
  }

  const data = operation.data
  const isTimedOut = operation.isTimedOut
  const config = isTimedOut
    ? { icon: XCircle, label: 'Timed out', color: 'text-amber-500', spin: false }
    : (statusConfig[data.status] ?? statusConfig.pending)
  const Icon = config.icon

  return (
    <div className={cn('flex items-start gap-2 rounded-md border px-3 py-2 text-sm', className)}>
      <Icon
        className={cn('mt-0.5 h-4 w-4 shrink-0', config.color, config.spin && 'animate-spin')}
      />
      <div className="min-w-0 flex-1">
        <p className={cn('font-medium', config.color)}>{config.label}</p>
        {isTimedOut && (
          <p className="mt-1 text-xs text-amber-500">Operation polling timed out. The operation may still be running on the server.</p>
        )}
        {data.error_message && (
          <p className="mt-1 text-xs text-destructive">{data.error_message}</p>
        )}
      </div>
    </div>
  )
}
