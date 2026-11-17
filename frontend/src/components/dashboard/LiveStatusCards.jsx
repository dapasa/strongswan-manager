import { Activity } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { useAllTunnelsLiveStatus } from '@/hooks/useTunnels'

const statusCards = [
  {
    key: 'up',
    label: 'Tunnels UP',
    activeColor: 'text-emerald-400',
    idleColor: 'text-muted-foreground',
    isAlert: (v) => false,
  },
  {
    key: 'down',
    label: 'Tunnels DOWN',
    activeColor: 'text-red-400',
    idleColor: 'text-muted-foreground',
    isAlert: (v) => v > 0,
  },
  {
    key: 'unknown',
    label: 'Unknown',
    activeColor: 'text-amber-400',
    idleColor: 'text-muted-foreground',
    isAlert: (v) => v > 0,
  },
]

/**
 * Live tunnel UP/DOWN/UNKNOWN cards. Shares the query key with TunnelListPage
 * so both views benefit from the same 30s cache.
 */
export default function LiveStatusCards() {
  const { data, isLoading } = useAllTunnelsLiveStatus()
  const summary = data?.summary ?? {}

  return (
    <div>
      <h2 className="mb-3 text-sm font-semibold text-muted-foreground uppercase tracking-wide">
        Live Tunnel Status
      </h2>
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        {statusCards.map((card) => {
          const value = summary[card.key] ?? 0
          const alert = card.isAlert(value)
          const color = alert ? card.activeColor : card.idleColor

          return (
            <Card key={card.key} className="bg-surface border-surface-border">
              <CardHeader className="flex flex-row items-center justify-between pb-2">
                <CardTitle className="text-sm font-medium text-muted-foreground">
                  {card.label}
                </CardTitle>
                <Activity className={`h-4 w-4 ${color}`} />
              </CardHeader>
              <CardContent>
                {isLoading ? (
                  <Skeleton className="h-8 w-16" />
                ) : (
                  <p className={`text-3xl font-bold ${color}`}>{value}</p>
                )}
              </CardContent>
            </Card>
          )
        })}
      </div>
      {!isLoading && data?.server_errors && Object.keys(data.server_errors).length > 0 && (
        <p className="mt-2 text-xs text-amber-400">
          Some VPN nodes could not be reached — live counts may be incomplete.
        </p>
      )}
    </div>
  )
}
