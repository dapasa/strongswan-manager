import { cn } from '@/lib/utils'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'

const statusConfig = {
  UP: {
    label: 'Up',
    dotColor: 'bg-emerald-400',
    variant: 'success',
  },
  DOWN: {
    label: 'Down',
    dotColor: 'bg-red-400',
    variant: 'error',
  },
  UNKNOWN: {
    label: 'Unknown',
    dotColor: 'bg-gray-400',
    variant: 'secondary',
  },
}

/**
 * Display a colored status badge with a dot indicator.
 *
 * @param {{ status: 'UP'|'DOWN'|'UNKNOWN'|'LOADING', className?: string }} props
 */
export default function StatusBadge({ status, className }) {
  if (status === 'LOADING') {
    return <Skeleton className="h-5 w-16 rounded-md" />
  }

  const config = statusConfig[status] ?? statusConfig.UNKNOWN

  return (
    <Badge variant={config.variant} className={cn('gap-1.5', className)}>
      <span className={cn('h-1.5 w-1.5 rounded-full', config.dotColor)} />
      {config.label}
    </Badge>
  )
}
