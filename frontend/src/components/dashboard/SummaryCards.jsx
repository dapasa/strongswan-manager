import { Network, Globe, Route, AlertTriangle, RefreshCw, Clock } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'

const cards = [
  {
    key: 'active_tunnels',
    label: 'Active Tunnels',
    icon: Network,
    color: 'text-emerald-400',
  },
  {
    key: 'active_routes',
    label: 'Active Routes',
    icon: Route,
    color: 'text-blue-400',
  },
  {
    key: 'active_iptables_rules',
    label: 'Firewall Rules',
    icon: Globe,
    color: 'text-violet-400',
  },
  {
    key: 'failed_syncs',
    label: 'Failed Syncs',
    icon: AlertTriangle,
    color: 'text-amber-400',
  },
  {
    key: 'pending_operations',
    label: 'Pending Operations',
    icon: Clock,
    color: 'text-orange-400',
  },
]

/**
 * Renders four metric cards in a responsive grid.
 *
 * @param {{ data: object|undefined, isLoading: boolean, isError: boolean, error: Error|null, refetch: Function }} props
 */
export default function SummaryCards({ data, isLoading, isError, error, refetch }) {
  if (isError) {
    return (
      <div className="rounded-lg border border-destructive/50 bg-destructive/10 p-4">
        <p className="text-sm text-destructive">
          Failed to load dashboard metrics: {error?.message ?? 'Unknown error'}
        </p>
        <button
          type="button"
          onClick={() => refetch()}
          className="mt-2 inline-flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors"
        >
          <RefreshCw className="h-3 w-3" />
          Retry
        </button>
      </div>
    )
  }

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
      {cards.map((card) => (
        <Card key={card.key} className="bg-surface border-surface-border">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              {card.label}
            </CardTitle>
            <card.icon className={`h-4 w-4 ${card.color}`} />
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <Skeleton className="h-8 w-16" />
            ) : (
              <p className={`text-3xl font-bold ${card.color}`}>
                {data?.[card.key] ?? 0}
              </p>
            )}
          </CardContent>
        </Card>
      ))}
    </div>
  )
}
