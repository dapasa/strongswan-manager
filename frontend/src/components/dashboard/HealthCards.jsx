import { Link } from 'react-router-dom'
import { AlertTriangle, Key, RefreshCw } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'

/**
 * Operational health cards — sync problems, PSK age, reconciler state.
 *
 * @param {{
 *   dashboardData: object|undefined,
 *   isDashboardLoading: boolean,
 *   reconcilerData: object|undefined,
 *   isReconcilerLoading: boolean,
 * }} props
 */
export default function HealthCards({
  dashboardData,
  isDashboardLoading,
  reconcilerData,
  isReconcilerLoading,
}) {
  const syncProblems = dashboardData?.sync_problems ?? 0
  const pskStaleCount = dashboardData?.psk_stale_count ?? 0
  const pskOldestDays = dashboardData?.psk_oldest_days ?? null
  const pskStaleTunnels = dashboardData?.psk_stale_tunnels ?? []

  const retryingCount = reconcilerData?.retrying?.length ?? 0
  const maxedCount = reconcilerData?.maxed?.length ?? 0
  const reconcilerEnabled = reconcilerData?.enabled ?? true

  return (
    <div>
      <h2 className="mb-3 text-sm font-semibold text-muted-foreground uppercase tracking-wide">
        Operational Health
      </h2>
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">

        {/* Sync Problems */}
        <Card className="bg-surface border-surface-border">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Sync Problems
            </CardTitle>
            <AlertTriangle
              className={`h-4 w-4 ${syncProblems > 0 ? 'text-amber-400' : 'text-muted-foreground'}`}
            />
          </CardHeader>
          <CardContent>
            {isDashboardLoading ? (
              <Skeleton className="h-8 w-16" />
            ) : (
              <>
                <p className={`text-3xl font-bold ${syncProblems > 0 ? 'text-amber-400' : 'text-muted-foreground'}`}>
                  {syncProblems}
                </p>
                <p className="mt-1 text-xs text-muted-foreground">
                  tunnels with failed / partial / pending sync
                </p>
              </>
            )}
          </CardContent>
        </Card>

        {/* PSK Age */}
        <Card className="bg-surface border-surface-border">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              PSK Health
            </CardTitle>
            <Key
              className={`h-4 w-4 ${pskStaleCount > 0 ? 'text-amber-400' : 'text-muted-foreground'}`}
            />
          </CardHeader>
          <CardContent>
            {isDashboardLoading ? (
              <Skeleton className="h-8 w-16" />
            ) : (
              <>
                <p className={`text-3xl font-bold ${pskStaleCount > 0 ? 'text-amber-400' : 'text-muted-foreground'}`}>
                  {pskStaleCount}
                </p>
                <p className="mt-1 text-xs text-muted-foreground">
                  {pskStaleCount > 0
                    ? `stale PSKs · oldest ${pskOldestDays}d`
                    : pskOldestDays !== null
                      ? `all current · oldest ${pskOldestDays}d`
                      : 'no tunnels'}
                </p>
                {pskStaleTunnels.length > 0 && (
                  <ul className="mt-2 space-y-0.5">
                    {pskStaleTunnels.slice(0, 5).map((t) => (
                      <li key={t.id} className="text-xs">
                        <Link
                          to={`/tunnels/${t.id}`}
                          className="text-amber-400 hover:underline"
                        >
                          {t.name}
                        </Link>
                        <span className="ml-1 text-muted-foreground">({t.psk_age_days}d)</span>
                      </li>
                    ))}
                    {pskStaleTunnels.length > 5 && (
                      <li className="text-xs text-muted-foreground">
                        +{pskStaleTunnels.length - 5} more
                      </li>
                    )}
                  </ul>
                )}
              </>
            )}
          </CardContent>
        </Card>

        {/* Reconciler */}
        <Card className="bg-surface border-surface-border">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Reconciler
            </CardTitle>
            <RefreshCw
              className={`h-4 w-4 ${
                maxedCount > 0
                  ? 'text-red-400'
                  : retryingCount > 0
                    ? 'text-amber-400'
                    : 'text-muted-foreground'
              }`}
            />
          </CardHeader>
          <CardContent>
            {isReconcilerLoading ? (
              <Skeleton className="h-8 w-16" />
            ) : (
              <>
                <p
                  className={`text-3xl font-bold ${
                    maxedCount > 0
                      ? 'text-red-400'
                      : retryingCount > 0
                        ? 'text-amber-400'
                        : 'text-muted-foreground'
                  }`}
                >
                  {retryingCount + maxedCount}
                </p>
                <p className="mt-1 text-xs text-muted-foreground">
                  {!reconcilerEnabled
                    ? 'reconciler disabled'
                    : maxedCount > 0
                      ? `${maxedCount} hit max attempts · ${retryingCount} retrying`
                      : retryingCount > 0
                        ? `${retryingCount} being retried`
                        : 'no tunnels in retry queue'}
                </p>
                {(reconcilerData?.maxed ?? []).length > 0 && (
                  <ul className="mt-2 space-y-0.5">
                    {reconcilerData.maxed.slice(0, 3).map((t) => (
                      <li key={t.tunnel_id} className="text-xs">
                        <Link
                          to={`/tunnels/${t.tunnel_id}`}
                          className="text-red-400 hover:underline"
                        >
                          {t.tunnel_name}
                        </Link>
                        <span className="ml-1 text-muted-foreground">
                          ({t.attempts} attempts)
                        </span>
                      </li>
                    ))}
                  </ul>
                )}
              </>
            )}
          </CardContent>
        </Card>

      </div>
    </div>
  )
}
