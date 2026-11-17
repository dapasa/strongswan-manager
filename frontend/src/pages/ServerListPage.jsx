import { useState } from 'react'
import { Link, useSearchParams, useNavigate } from 'react-router-dom'
import { Plus, Pencil, Trash2, Search, Server, ChevronLeft, ChevronRight, CheckCircle2, XCircle, Clock, Plug, Activity, RefreshCw, AlertTriangle } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet'
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip'
import RoleGuard from '@/components/shared/RoleGuard'
import ConfirmDialog from '@/components/shared/ConfirmDialog'
import EmptyState from '@/components/shared/EmptyState'
import { useServers, useDeleteServer, useTestConnection, useServerDrift } from '@/hooks/useServers'
import { DEFAULT_PAGE_SIZE } from '@/lib/constants'
import { cn } from '@/lib/utils'

function shortenSha(sha) {
  return sha ? sha.slice(0, 8) : '—'
}

function DriftStatusBadge({ status }) {
  if (status === 'in_sync') {
    return (
      <Badge variant="outline" className="border-success/50 text-success shrink-0">
        <CheckCircle2 className="mr-1 h-3 w-3" />
        In Sync
      </Badge>
    )
  }
  if (status === 'drifted') {
    return (
      <Badge variant="outline" className="border-amber-500/50 text-amber-500 shrink-0">
        <AlertTriangle className="mr-1 h-3 w-3" />
        Drifted
      </Badge>
    )
  }
  return (
    <Badge variant="outline" className="border-destructive/50 text-destructive shrink-0">
      <XCircle className="mr-1 h-3 w-3" />
      Missing
    </Badge>
  )
}

function TunnelDriftSection({ tunnel }) {
  const allPaths = [...new Set([
    ...Object.keys(tunnel.expected_hashes),
    ...Object.keys(tunnel.actual_hashes),
  ])]

  return (
    <div className="rounded-lg border border-surface-border p-3 space-y-2">
      <div className="flex items-center justify-between gap-2">
        <Link
          to={`/tunnels/${tunnel.tunnel_id}`}
          className="text-sm font-medium hover:underline truncate"
        >
          {tunnel.tunnel_name}
        </Link>
        <DriftStatusBadge status={tunnel.status} />
      </div>
      {tunnel.status !== 'in_sync' && allPaths.length > 0 && (
        <TooltipProvider>
          <div className="mt-2 space-y-1">
            <div className="flex gap-2 text-xs text-muted-foreground font-medium pb-1 border-b border-surface-border">
              <span className="flex-1 min-w-0">Path</span>
              <span className="w-20 text-right shrink-0">Expected</span>
              <span className="w-20 text-right shrink-0">Actual</span>
            </div>
            {allPaths.map((path) => {
              const exp = tunnel.expected_hashes[path]
              const act = tunnel.actual_hashes[path]
              const isMismatch = exp !== act
              return (
                <div
                  key={path}
                  className={cn(
                    'flex gap-2 items-center text-xs',
                    isMismatch ? 'text-destructive' : 'text-muted-foreground',
                  )}
                >
                  <span className="font-mono flex-1 min-w-0 break-all">{path}</span>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <span className="font-mono w-20 text-right shrink-0 cursor-default">
                        {shortenSha(exp)}
                      </span>
                    </TooltipTrigger>
                    <TooltipContent side="left">
                      <span className="font-mono">{exp ?? '—'}</span>
                    </TooltipContent>
                  </Tooltip>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <span className="font-mono w-20 text-right shrink-0 cursor-default">
                        {act ? shortenSha(act) : '—'}
                      </span>
                    </TooltipTrigger>
                    <TooltipContent side="left">
                      <span className="font-mono">{act ?? '—'}</span>
                    </TooltipContent>
                  </Tooltip>
                </div>
              )
            })}
          </div>
        </TooltipProvider>
      )}
    </div>
  )
}

function DriftReport({ data, onRecheck, isChecking }) {
  const inSync = data.tunnels.filter((t) => t.status === 'in_sync').length
  const drifted = data.tunnels.filter((t) => t.status === 'drifted').length
  const missing = data.tunnels.filter((t) => t.status === 'missing_on_node').length
  const orphans = data.orphan_files.length

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <span className="text-xs text-muted-foreground">
          Checked {new Date(data.checked_at).toLocaleString()}
        </span>
        <Button variant="outline" size="sm" onClick={onRecheck} disabled={isChecking}>
          <RefreshCw className={cn('h-3.5 w-3.5', isChecking && 'animate-spin')} />
          Re-check
        </Button>
      </div>

      <div className="flex flex-wrap gap-3 text-sm">
        <span className="text-success">{inSync} in sync</span>
        {drifted > 0 && <span className="text-amber-500">{drifted} drifted</span>}
        {missing > 0 && <span className="text-destructive">{missing} missing</span>}
        {orphans > 0 && <span className="text-muted-foreground">{orphans} orphans</span>}
      </div>

      {data.tunnels.map((tunnel) => (
        <TunnelDriftSection key={tunnel.tunnel_id} tunnel={tunnel} />
      ))}

      {data.orphan_files.length > 0 && (
        <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 space-y-2">
          <h4 className="text-sm font-medium text-amber-500">
            Orphan Files ({data.orphan_files.length})
          </h4>
          <ul className="space-y-1">
            {data.orphan_files.map((path) => (
              <li key={path} className="font-mono text-xs text-muted-foreground break-all">
                {path}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

function StatusBadge({ status }) {
  if (!status) {
    return (
      <Badge variant="outline" className="text-muted-foreground">
        <Clock className="mr-1 h-3 w-3" />
        Never checked
      </Badge>
    )
  }
  if (status === 'reachable') {
    return (
      <Badge variant="outline" className="border-success/50 text-success">
        <CheckCircle2 className="mr-1 h-3 w-3" />
        Reachable
      </Badge>
    )
  }
  return (
    <Badge variant="outline" className="border-destructive/50 text-destructive">
      <XCircle className="mr-1 h-3 w-3" />
      Unreachable
    </Badge>
  )
}

export default function ServerListPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const navigate = useNavigate()
  const [search, setSearch] = useState('')
  const [deleteTarget, setDeleteTarget] = useState(null)
  const [testing, setTesting] = useState(new Set())
  const [driftServer, setDriftServer] = useState(null)

  const drift = useServerDrift(driftServer?.id, { enabled: !!driftServer })

  const page = Number(searchParams.get('page')) || 1

  const servers = useServers({
    page,
    pageSize: DEFAULT_PAGE_SIZE,
    search: search || undefined,
  })
  const deleteMutation = useDeleteServer()
  const testConnection = useTestConnection()

  const items = servers.data?.items ?? []
  const totalPages = servers.data ? Math.ceil(servers.data.total / DEFAULT_PAGE_SIZE) : 0

  const goToPage = (newPage) => {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev)
      if (newPage <= 1) {
        next.delete('page')
      } else {
        next.set('page', String(newPage))
      }
      return next
    })
  }

  async function handleTestConnection(serverId) {
    setTesting((prev) => new Set(prev).add(serverId))
    try {
      await testConnection.mutateAsync(serverId)
    } finally {
      setTesting((prev) => {
        const next = new Set(prev)
        next.delete(serverId)
        return next
      })
    }
  }

  async function handleDelete() {
    if (!deleteTarget) return
    await deleteMutation.mutateAsync(deleteTarget.id)
    setDeleteTarget(null)
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Servers</h1>
          <p className="text-sm text-muted-foreground">
            Manage server connections (SSH and SSM).
          </p>
        </div>
        <RoleGuard requiredRole="admin">
          <Button asChild>
            <Link to="/servers/new">
              <Plus className="h-4 w-4" />
              Add Server
            </Link>
          </Button>
        </RoleGuard>
      </div>

      {/* Search */}
      <div className="flex flex-wrap items-end gap-3">
        <div className="relative max-w-sm flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search servers..."
            value={search}
            onChange={(e) => {
              setSearch(e.target.value)
              goToPage(1)
            }}
            className="pl-9"
          />
        </div>
      </div>

      {/* Table */}
      {servers.isLoading ? (
        <div className="space-y-3">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-12 w-full" />
          ))}
        </div>
      ) : servers.isError ? (
        <div className="rounded-lg border border-destructive/50 bg-destructive/10 p-4">
          <p className="text-sm text-destructive">
            Failed to load servers: {servers.error?.message ?? 'Unknown error'}
          </p>
          <button
            type="button"
            onClick={() => servers.refetch()}
            className="mt-2 text-xs text-muted-foreground hover:text-foreground transition-colors"
          >
            Retry
          </button>
        </div>
      ) : items.length === 0 ? (
        <EmptyState
          icon={Server}
          title="No servers configured yet"
          description="Add your first server to get started."
          action={
            <RoleGuard requiredRole="admin">
              <Button asChild variant="outline">
                <Link to="/servers/new">
                  <Plus className="h-4 w-4" />
                  Add Server
                </Link>
              </Button>
            </RoleGuard>
          }
        />
      ) : (
        <>
        <div className="rounded-lg border border-surface-border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Engine</TableHead>
                <TableHead>Connection</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Active</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((server) => (
                <TableRow
                  key={server.id}
                  className={testing.has(server.id) ? 'opacity-60' : 'cursor-pointer'}
                  onClick={() => {
                    if (!testing.has(server.id)) {
                      navigate(`/servers/${server.id}/edit`)
                    }
                  }}
                >
                  <TableCell className="font-medium">{server.name}</TableCell>
                  <TableCell>
                    <Badge
                      variant="outline"
                      className={
                        server.connection_type === 'ssm'
                          ? 'border-blue-500/50 text-blue-500'
                          : 'border-violet-500/50 text-violet-500'
                      }
                    >
                      {server.connection_type?.toUpperCase() ?? 'SSH'}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Badge
                      variant="outline"
                      className={
                        server.ipsec_engine === 'swanctl'
                          ? 'border-emerald-500/50 text-emerald-500'
                          : 'border-amber-500/50 text-amber-500'
                      }
                    >
                      {server.ipsec_engine?.toUpperCase() ?? 'STROKE'}
                    </Badge>
                  </TableCell>
                  <TableCell className="font-mono text-sm text-muted-foreground">
                    {server.connection_type === 'ssm'
                      ? server.ec2_instance_id ?? '—'
                      : server.hostname ?? '—'}
                  </TableCell>
                  <TableCell>
                    <StatusBadge status={server.last_check_status} />
                  </TableCell>
                  <TableCell>
                    <Badge variant={server.is_active ? 'default' : 'secondary'}>
                      {server.is_active ? 'Active' : 'Inactive'}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-right">
                    <div className="flex items-center justify-end gap-1" onClick={(e) => e.stopPropagation()}>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => setDriftServer({ id: server.id, name: server.name })}
                      >
                        <Activity className="h-4 w-4" />
                        Drift
                      </Button>
                      <RoleGuard requiredRole="operator">
                        <Button
                          variant="ghost"
                          size="sm"
                          disabled={testing.has(server.id)}
                          onClick={() => handleTestConnection(server.id)}
                        >
                          <Plug className={testing.has(server.id) ? 'h-4 w-4 animate-pulse' : 'h-4 w-4'} />
                          {testing.has(server.id) ? 'Testing...' : 'Test'}
                        </Button>
                      </RoleGuard>
                      <RoleGuard requiredRole="admin">
                        <Button variant="ghost" size="icon" asChild>
                          <Link to={`/servers/${server.id}/edit`}>
                            <Pencil className="h-4 w-4" />
                          </Link>
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="text-muted-foreground hover:text-destructive"
                          onClick={() => setDeleteTarget(server)}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </RoleGuard>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between">
            <p className="text-sm text-muted-foreground">
              Showing {(page - 1) * DEFAULT_PAGE_SIZE + 1}
              &ndash;
              {Math.min(page * DEFAULT_PAGE_SIZE, servers.data.total)} of {servers.data.total} servers
            </p>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                disabled={page <= 1}
                onClick={() => goToPage(page - 1)}
              >
                <ChevronLeft className="h-4 w-4" />
                Previous
              </Button>
              <span className="text-sm text-muted-foreground">
                Page {page} of {totalPages}
              </span>
              <Button
                variant="outline"
                size="sm"
                disabled={page >= totalPages}
                onClick={() => goToPage(page + 1)}
              >
                Next
                <ChevronRight className="h-4 w-4" />
              </Button>
            </div>
          </div>
        )}
        </>
      )}

      {/* Delete confirmation */}
      <ConfirmDialog
        open={!!deleteTarget}
        onOpenChange={(open) => !open && setDeleteTarget(null)}
        title="Delete Server"
        description={`Are you sure you want to delete "${deleteTarget?.name}"? This action cannot be undone.`}
        confirmLabel="Delete"
        variant="destructive"
        loading={deleteMutation.isPending}
        onConfirm={handleDelete}
      />

      {/* Drift sheet */}
      <Sheet open={!!driftServer} onOpenChange={(open) => !open && setDriftServer(null)}>
        <SheetContent side="right" className="sm:max-w-xl flex flex-col">
          <SheetHeader>
            <SheetTitle>Config Drift — {driftServer?.name}</SheetTitle>
          </SheetHeader>
          <div className="flex-1 overflow-y-auto space-y-4 mt-2 pr-1">
            {drift.isLoading && (
              <div className="space-y-3">
                {Array.from({ length: 4 }).map((_, i) => (
                  <Skeleton key={i} className="h-10 w-full" />
                ))}
              </div>
            )}
            {drift.isError && !drift.isFetching && (
              <div className="rounded-lg border border-destructive/50 bg-destructive/10 p-4">
                <p className="text-sm text-destructive">
                  {drift.error?.response?.data?.detail ?? drift.error?.message ?? 'Failed to load drift report'}
                </p>
                <button
                  type="button"
                  onClick={() => drift.refetch()}
                  className="mt-2 text-xs text-muted-foreground hover:text-foreground transition-colors"
                >
                  Retry
                </button>
              </div>
            )}
            {drift.data && (
              <DriftReport
                data={drift.data}
                onRecheck={() => drift.refetch()}
                isChecking={drift.isFetching}
              />
            )}
          </div>
        </SheetContent>
      </Sheet>
    </div>
  )
}
