import { RefreshCw } from 'lucide-react'
import { useDashboard } from '@/hooks/useDashboard'
import { useRecentActivity } from '@/hooks/useRecentActivity'
import SummaryCards from '@/components/dashboard/SummaryCards'
import RecentActivity from '@/components/dashboard/RecentActivity'

export default function DashboardPage() {
  const dashboard = useDashboard()
  const activity = useRecentActivity()

  const lastRefresh = dashboard.dataUpdatedAt
    ? new Date(dashboard.dataUpdatedAt).toLocaleTimeString()
    : null

  const handleRefresh = () => {
    dashboard.refetch()
    activity.refetch()
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Dashboard</h1>
          <p className="text-sm text-muted-foreground">
            Overview of VPN tunnels and system status.
          </p>
        </div>

        <div className="flex items-center gap-3">
          {lastRefresh && (
            <span className="text-xs text-muted-foreground">
              Last update: {lastRefresh}
            </span>
          )}
          <button
            type="button"
            onClick={handleRefresh}
            disabled={dashboard.isFetching}
            className="inline-flex items-center gap-1.5 rounded-md border border-surface-border bg-surface px-3 py-1.5 text-xs font-medium text-muted-foreground hover:text-foreground transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${dashboard.isFetching ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      <SummaryCards
        data={dashboard.data}
        isLoading={dashboard.isLoading}
        isError={dashboard.isError}
        error={dashboard.error}
        refetch={dashboard.refetch}
      />

      <RecentActivity
        data={activity.data}
        isLoading={activity.isLoading}
        isError={activity.isError}
      />
    </div>
  )
}
