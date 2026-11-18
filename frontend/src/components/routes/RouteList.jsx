import { useState } from 'react'
import { Route, Loader2, ChevronDown, ChevronUp } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import EmptyState from '@/components/shared/EmptyState'
import { useRoutes } from '@/hooks/useRoutes'

const syncStatusConfig = {
  synced: { label: 'Applied', variant: 'success', inProgress: false },
  pending: { label: 'Pending', variant: 'warning', inProgress: true },
  cloning: { label: 'Cloning...', variant: 'default', inProgress: true },
  planning: { label: 'Planning...', variant: 'default', inProgress: true },
  applying: { label: 'Applying...', variant: 'warning', inProgress: true },
  pushing: { label: 'Pushing...', variant: 'default', inProgress: true },
  failed: { label: 'Failed', variant: 'error', inProgress: false },
  pending_delete: { label: 'Deleting...', variant: 'warning', inProgress: true },
}

function RouteSyncBadge({ status }) {
  const config = syncStatusConfig[status] ?? { label: status, variant: 'secondary', inProgress: false }
  return (
    <Badge variant={config.variant} className="gap-1.5">
      {config.inProgress && <Loader2 className="h-3 w-3 animate-spin" />}
      {config.label}
    </Badge>
  )
}

function RouteErrorDetail({ error }) {
  const [expanded, setExpanded] = useState(false)
  const isLong = error.length > 80

  if (!isLong) {
    return (
      <p className="mt-1 max-w-xs text-xs text-destructive">{error}</p>
    )
  }

  return (
    <div className="mt-1 max-w-sm">
      <button
        type="button"
        onClick={() => setExpanded((v) => !v)}
        className="flex items-center gap-1 text-xs text-destructive hover:underline"
      >
        {expanded ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
        {expanded ? 'Hide error' : 'Show error'}
      </button>
      {expanded && (
        <pre className="mt-1 max-h-32 overflow-auto whitespace-pre-wrap rounded bg-destructive/5 p-2 text-xs text-destructive">
          {error}
        </pre>
      )}
    </div>
  )
}

/**
 * Displays the route table for a tunnel (read-only).
 *
 * Route provisioning via Terragrunt was removed from the manager; create,
 * delete and retry come back with the AWS-API-backed redesign (sc-31774).
 *
 * @param {{ tunnelId: number|string }} props
 */
export default function RouteList({ tunnelId }) {
  const routes = useRoutes(tunnelId)

  if (routes.isLoading) {
    return (
      <Card className="bg-surface border-surface-border">
        <CardHeader>
          <CardTitle>Routes</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <Skeleton className="h-8 w-full" />
          <Skeleton className="h-8 w-full" />
          <Skeleton className="h-8 w-full" />
        </CardContent>
      </Card>
    )
  }

  if (routes.isError) {
    return (
      <Card className="bg-surface border-surface-border">
        <CardContent className="py-6">
          <p className="text-sm text-destructive">
            Failed to load routes: {routes.error?.response?.data?.detail ?? routes.error?.message ?? 'Unknown error'}
          </p>
        </CardContent>
      </Card>
    )
  }

  const data = routes.data ?? []

  return (
    <Card className="bg-surface border-surface-border">
      <CardHeader className="flex flex-row items-center justify-between space-y-0">
        <CardTitle>Routes ({data.length})</CardTitle>
      </CardHeader>
      <CardContent>
        {data.length === 0 ? (
          <EmptyState
            icon={Route}
            title="No routes for this tunnel"
            description="Route management is being redesigned and is read-only for now."
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Destination CIDR</TableHead>
                <TableHead>Description</TableHead>
                <TableHead>Status</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.map((route) => (
                <TableRow key={route.id}>
                  <TableCell className="font-mono text-sm">{route.cidr}</TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {route.description ?? '-'}
                  </TableCell>
                  <TableCell>
                    <RouteSyncBadge status={route.sync_status} />
                    {route.sync_error && (
                      <RouteErrorDetail error={route.sync_error} />
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  )
}
