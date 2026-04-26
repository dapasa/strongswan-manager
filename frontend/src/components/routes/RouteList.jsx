import { useState } from 'react'
import { Trash2, RotateCcw, Route, Loader2, ChevronDown, ChevronUp } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
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
import RoleGuard from '@/components/shared/RoleGuard'
import ConfirmDialog from '@/components/shared/ConfirmDialog'
import AsyncOperationStatus from '@/components/shared/AsyncOperationStatus'
import EmptyState from '@/components/shared/EmptyState'
import { useRoutes, useDeleteRoute, useRetryRoute } from '@/hooks/useRoutes'
import RouteForm from './RouteForm'

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
 * Displays the route table for a tunnel with CRUD actions.
 *
 * @param {{ tunnelId: number|string }} props
 */
export default function RouteList({ tunnelId }) {
  const routes = useRoutes(tunnelId)
  const deleteMutation = useDeleteRoute(tunnelId)
  const retryMutation = useRetryRoute(tunnelId)
  const [deleteTarget, setDeleteTarget] = useState(null)
  const [activeOperationId, setActiveOperationId] = useState(null)

  async function handleDelete() {
    if (!deleteTarget) return
    const result = await deleteMutation.mutateAsync(deleteTarget.id)
    setActiveOperationId(result.operation_id)
    setDeleteTarget(null)
  }

  async function handleRetry(routeId) {
    const result = await retryMutation.mutateAsync(routeId)
    setActiveOperationId(result.operation_id)
  }

  function handleOperationCompleted() {
    setActiveOperationId(null)
    routes.refetch()
  }

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
        <RoleGuard requiredRole="operator">
          <RouteForm tunnelId={tunnelId} />
        </RoleGuard>
      </CardHeader>
      <CardContent>
        {activeOperationId && (
          <div className="mb-4">
            <AsyncOperationStatus
              operationId={activeOperationId}
              onCompleted={handleOperationCompleted}
            />
          </div>
        )}

        {data.length === 0 ? (
          <EmptyState
            icon={Route}
            title="No routes for this tunnel"
            description="Add a route to direct traffic through this VPN tunnel."
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Destination CIDR</TableHead>
                <TableHead>Description</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Actions</TableHead>
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
                  <TableCell className="text-right">
                    <RoleGuard requiredRole="operator">
                      <div className="flex items-center justify-end gap-1">
                        {route.sync_status === 'failed' && (
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => handleRetry(route.id)}
                            disabled={retryMutation.isPending}
                            title="Retry"
                          >
                            <RotateCcw className="h-4 w-4" />
                          </Button>
                        )}
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => setDeleteTarget(route)}
                          disabled={deleteMutation.isPending || route.sync_status === 'pending_delete'}
                          className="text-muted-foreground hover:text-destructive"
                          title="Delete"
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </RoleGuard>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>

      <ConfirmDialog
        open={!!deleteTarget}
        onOpenChange={(open) => { if (!open) setDeleteTarget(null) }}
        title="Delete Route"
        description={`Are you sure you want to delete the route "${deleteTarget?.cidr}"? This will remove the route from the VPN tunnel.`}
        confirmLabel="Delete"
        variant="destructive"
        loading={deleteMutation.isPending}
        onConfirm={handleDelete}
      />
    </Card>
  )
}
