import { useState } from 'react'
import { Route, Loader2, ChevronDown, ChevronUp, Plus, Trash2, RotateCcw } from 'lucide-react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
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
import EmptyState from '@/components/shared/EmptyState'
import { useRoutes, useCreateRoute, useDeleteRoute, useRetryRoute } from '@/hooks/useRoutes'
import { getErrorMessage } from '@/lib/toast'

const cidrRegex = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\/(?:3[0-2]|[12]?\d)$/

const addRouteSchema = z.object({
  cidr: z.string().regex(cidrRegex, 'Enter a valid CIDR (e.g. 10.100.1.0/24)'),
  description: z.string().optional().default(''),
})

const syncStatusConfig = {
  synced: { label: 'Synced', variant: 'success', inProgress: false },
  pending: { label: 'Pending', variant: 'warning', inProgress: true },
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

function TableOutcomesDetail({ outcomes }) {
  const [expanded, setExpanded] = useState(false)
  if (!outcomes || Object.keys(outcomes).length === 0) return null

  const successStates = new Set(['ok', 'already_exists_same_target', 'not_found_ok'])

  return (
    <div className="mt-1.5">
      <button
        type="button"
        onClick={() => setExpanded((v) => !v)}
        className="flex items-center gap-1 text-xs text-muted-foreground hover:underline"
      >
        {expanded ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
        {expanded ? 'Hide table details' : 'Show table details'}
      </button>
      {expanded && (
        <div className="mt-1 space-y-0.5 rounded bg-surface-hover p-2 text-xs font-mono">
          {Object.entries(outcomes).map(([rtbId, outcome]) => (
            <div key={rtbId} className="flex flex-wrap gap-x-2">
              <span className="text-muted-foreground">{rtbId}</span>
              <span className={successStates.has(outcome.status) ? 'text-success' : 'text-destructive'}>
                {outcome.status}
              </span>
              {outcome.error && (
                <span className="text-destructive">{outcome.error}</span>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function RouteErrorDetail({ error, tableOutcomes }) {
  const [expanded, setExpanded] = useState(false)
  const isLong = error.length > 80

  return (
    <div className="mt-1 max-w-sm">
      {!isLong ? (
        <p className="text-xs text-destructive">{error}</p>
      ) : (
        <>
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
        </>
      )}
      <TableOutcomesDetail outcomes={tableOutcomes} />
    </div>
  )
}

/**
 * Inline form for adding a new route to a tunnel.
 *
 * @param {{
 *   tunnelId: number|string,
 *   remoteCidrs?: string[],
 *   onSuccess?: () => void,
 * }} props
 */
function AddRouteForm({ tunnelId, remoteCidrs, onSuccess }) {
  const createMutation = useCreateRoute(tunnelId)

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm({
    resolver: zodResolver(addRouteSchema),
    defaultValues: { cidr: '', description: '' },
  })

  async function onSubmit(values) {
    await createMutation.mutateAsync({
      cidr: values.cidr,
      description: values.description || null,
    })
    reset()
    onSuccess?.()
  }

  return (
    <div className="mb-4 space-y-3 rounded-lg border border-surface-border bg-surface p-4">
      <h4 className="text-sm font-medium">New Route</h4>

      <form onSubmit={handleSubmit(onSubmit)} className="space-y-3">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div className="space-y-1.5">
            <Label htmlFor="route-cidr">Destination CIDR *</Label>
            <Input
              id="route-cidr"
              placeholder="10.100.1.0/24"
              className="font-mono"
              {...register('cidr')}
            />
            {errors.cidr && (
              <p className="text-xs text-destructive">{errors.cidr.message}</p>
            )}
            {remoteCidrs?.length > 0 && (
              <p className="text-xs text-muted-foreground">
                Tunnel remote CIDRs: {remoteCidrs.join(', ')}
              </p>
            )}
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="route-desc">Description</Label>
            <Input
              id="route-desc"
              placeholder="Optional label"
              {...register('description')}
            />
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Button type="submit" size="sm" disabled={createMutation.isPending}>
            {createMutation.isPending ? 'Creating...' : 'Create Route'}
          </Button>
          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={() => { reset(); onSuccess?.() }}
            disabled={createMutation.isPending}
          >
            Cancel
          </Button>
        </div>

        {createMutation.isError && (
          <p className="text-xs text-destructive">
            {getErrorMessage(createMutation.error)}
          </p>
        )}
      </form>
    </div>
  )
}

/**
 * Displays the route table for a tunnel with CRUD actions.
 *
 * Operators and admins can add, retry, and delete routes.
 * Viewers see the list read-only.
 *
 * @param {{ tunnelId: number|string, remoteCidrs?: string[] }} props
 */
export default function RouteList({ tunnelId, remoteCidrs }) {
  const routes = useRoutes(tunnelId)
  const deleteMutation = useDeleteRoute(tunnelId)
  const retryMutation = useRetryRoute(tunnelId)
  const [showAddForm, setShowAddForm] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState(null)

  async function handleDelete() {
    if (!deleteTarget) return
    await deleteMutation.mutateAsync(deleteTarget.id)
    setDeleteTarget(null)
  }

  async function handleRetry(routeId) {
    await retryMutation.mutateAsync(routeId)
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
            Failed to load routes:{' '}
            {routes.error?.response?.data?.detail ?? routes.error?.message ?? 'Unknown error'}
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
          <Button
            variant="outline"
            size="sm"
            onClick={() => setShowAddForm((v) => !v)}
            className="gap-1.5"
          >
            {showAddForm
              ? <ChevronUp className="h-3.5 w-3.5" />
              : <Plus className="h-3.5 w-3.5" />}
            {showAddForm ? 'Cancel' : 'Add Route'}
          </Button>
        </RoleGuard>
      </CardHeader>
      <CardContent>
        {showAddForm && (
          <AddRouteForm
            tunnelId={tunnelId}
            remoteCidrs={remoteCidrs}
            onSuccess={() => setShowAddForm(false)}
          />
        )}

        {data.length === 0 ? (
          <EmptyState
            icon={Route}
            title="No routes for this tunnel"
            description="Add a route to forward traffic through this tunnel via the VPC route tables."
          />
        ) : (
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Destination CIDR</TableHead>
                  <TableHead>Description</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Target ENI</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.map((route) => (
                  <TableRow key={route.id}>
                    <TableCell className="font-mono text-sm">{route.cidr}</TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {route.description ?? '—'}
                    </TableCell>
                    <TableCell>
                      <RouteSyncBadge status={route.sync_status} />
                      {route.sync_error && (
                        <RouteErrorDetail
                          error={route.sync_error}
                          tableOutcomes={route.table_outcomes}
                        />
                      )}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {route.target_eni ?? '—'}
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
                              title="Retry sync"
                            >
                              <RotateCcw className="h-4 w-4" />
                            </Button>
                          )}
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => setDeleteTarget(route)}
                            disabled={
                              deleteMutation.isPending ||
                              route.sync_status === 'pending_delete'
                            }
                            className="text-muted-foreground hover:text-destructive"
                            title="Delete route"
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
          </div>
        )}
      </CardContent>

      <ConfirmDialog
        open={!!deleteTarget}
        onOpenChange={(open) => { if (!open) setDeleteTarget(null) }}
        title="Delete Route"
        description={`Delete route ${deleteTarget?.cidr}? This removes it from all AWS route tables. This action cannot be undone.`}
        confirmLabel="Delete"
        variant="destructive"
        loading={deleteMutation.isPending}
        onConfirm={handleDelete}
      />
    </Card>
  )
}
