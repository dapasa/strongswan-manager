import { Link } from 'react-router-dom'
import { ArrowRight, Clock } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'

/**
 * Return a human-readable relative time string (e.g. "2 minutes ago").
 * @param {string} isoString
 */
function timeAgo(isoString) {
  const now = Date.now()
  const then = new Date(isoString).getTime()
  const diffSec = Math.max(0, Math.floor((now - then) / 1000))

  if (diffSec < 60) return 'just now'
  const diffMin = Math.floor(diffSec / 60)
  if (diffMin < 60) return `${diffMin}m ago`
  const diffHr = Math.floor(diffMin / 60)
  if (diffHr < 24) return `${diffHr}h ago`
  const diffDay = Math.floor(diffHr / 24)
  return `${diffDay}d ago`
}

/** Map action verbs to badge variants. */
const actionVariant = {
  create: 'success',
  update: 'default',
  delete: 'destructive',
  retry: 'warning',
  login: 'secondary',
}

/**
 * Shows the 5 most recent audit log entries.
 *
 * @param {{ data: Array, isLoading: boolean, isError: boolean }} props
 */
export default function RecentActivity({ data, isLoading, isError }) {
  return (
    <Card className="bg-surface border-surface-border">
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="text-base font-semibold">Recent Activity</CardTitle>
        <Link
          to="/audit"
          className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
        >
          View all
          <ArrowRight className="h-3 w-3" />
        </Link>
      </CardHeader>
      <CardContent>
        {isError && (
          <p className="text-sm text-destructive">Failed to load recent activity.</p>
        )}

        {isLoading && (
          <div className="space-y-4">
            {Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className="flex items-center gap-3">
                <Skeleton className="h-4 w-4 rounded-full" />
                <div className="flex-1 space-y-1.5">
                  <Skeleton className="h-3 w-3/4" />
                  <Skeleton className="h-2.5 w-1/2" />
                </div>
              </div>
            ))}
          </div>
        )}

        {!isLoading && !isError && data.length === 0 && (
          <p className="py-6 text-center text-sm text-muted-foreground">
            No recent activity
          </p>
        )}

        {!isLoading && !isError && data.length > 0 && (
          <ul className="space-y-3">
            {data.map((entry) => (
              <li
                key={entry.id}
                className="flex items-start gap-3 rounded-md border border-surface-border p-3"
              >
                <Clock className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <Badge variant={actionVariant[entry.action] ?? 'outline'}>
                      {entry.action}
                    </Badge>
                    <span className="text-sm font-medium text-foreground capitalize">
                      {entry.entity_type}
                    </span>
                    {entry.entity_id != null && (
                      <span className="text-xs text-muted-foreground">
                        #{entry.entity_id}
                      </span>
                    )}
                  </div>
                  <div className="mt-1 flex items-center gap-2 text-xs text-muted-foreground">
                    <span>{entry.user?.display_name ?? entry.user?.email ?? 'System'}</span>
                    <span>&middot;</span>
                    <time dateTime={entry.created_at} title={new Date(entry.created_at).toLocaleString()}>
                      {timeAgo(entry.created_at)}
                    </time>
                  </div>
                </div>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  )
}
