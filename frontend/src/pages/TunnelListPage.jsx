import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { Plus, Eye, Pencil, Trash2, Search, Network, ChevronLeft, ChevronRight, CheckCircle2, XCircle, Clock, AlertTriangle, Activity } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
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
import TunnelStatusCell from '@/components/tunnels/TunnelStatusCell'
import { useTunnels, useDeleteTunnel, useCheckTunnelStatus } from '@/hooks/useTunnels'
import { DEFAULT_PAGE_SIZE } from '@/lib/constants'

/**
 * Parse the sync_error to extract per-instance status.
 * Expected format first line: "SSM: Reload X/Y failed — primary: FAILED | secondary: OK"
 */
function parseSyncInstances(syncError) {
  if (!syncError) return null
  const match = syncError.match(/— (.+?)(\n|$)/)
  if (!match) return null
  return match[1].split('|').map((part) => {
    const trimmed = part.trim()
    const [name, status] = trimmed.split(':').map((s) => s.trim())
    return { name, ok: status === 'OK' }
  })
}

function SyncStatusCell({ syncStatus, syncError }) {
  if (syncStatus === 'synced') {
    return (
      <div className="flex items-center gap-1.5 text-xs">
        <CheckCircle2 className="h-3.5 w-3.5 text-success" />
        <span className="text-success">Primary: OK</span>
        <span className="text-muted-foreground">|</span>
        <span className="text-success">Secondary: OK</span>
      </div>
    )
  }

  if (syncStatus === 'pending') {
    return (
      <div className="flex items-center gap-1.5 text-xs">
        <Clock className="h-3.5 w-3.5 text-warning" />
        <span className="text-warning">syncing...</span>
      </div>
    )
  }

  // Failed — try to parse per-instance status
  const instances = parseSyncInstances(syncError)
  if (instances) {
    return (
      <div className="flex items-center gap-1.5 text-xs" title={syncError}>
        {instances.map((inst, i) => (
          <span key={inst.name}>
            {i > 0 && <span className="text-muted-foreground"> | </span>}
            <span className="capitalize">{inst.name}: </span>
            <span className={inst.ok ? 'text-success' : 'text-destructive'}>
              {inst.ok ? 'OK' : 'Fail'}
            </span>
          </span>
        ))}
      </div>
    )
  }

  // Fallback — generic failed
  return (
    <div className="flex items-center gap-1.5 text-xs" title={syncError}>
      <XCircle className="h-3.5 w-3.5 text-destructive" />
      <span className="text-destructive">failed</span>
    </div>
  )
}

const ALL = '__all__'
const STATUS_OPTIONS = [
  { value: ALL, label: 'All statuses' },
  { value: 'up', label: 'UP' },
  { value: 'down', label: 'DOWN' },
  { value: 'unknown', label: 'Unknown' },
]

export default function TunnelListPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState(ALL)
  const [deleteTarget, setDeleteTarget] = useState(null)
  const [selected, setSelected] = useState(new Set())
  const [checking, setChecking] = useState(new Set())

  const page = Number(searchParams.get('page')) || 1

  const tunnels = useTunnels({
    page,
    pageSize: DEFAULT_PAGE_SIZE,
    search: search || undefined,
    status: statusFilter !== ALL ? statusFilter : undefined,
  })
  const deleteMutation = useDeleteTunnel()
  const checkStatus = useCheckTunnelStatus()

  const items = tunnels.data?.items ?? []
  const totalPages = tunnels.data ? Math.ceil(tunnels.data.total / DEFAULT_PAGE_SIZE) : 0

  function toggleSelected(id) {
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(id)) {
        next.delete(id)
      } else {
        next.add(id)
      }
      return next
    })
  }

  function toggleSelectAll() {
    if (selected.size === items.length) {
      setSelected(new Set())
    } else {
      setSelected(new Set(items.map((t) => t.id)))
    }
  }

  async function handleCheckStatus() {
    const ids = [...selected]
    setChecking(new Set(ids))
    const promises = ids.map((id) =>
      checkStatus.mutateAsync(id).finally(() => {
        setChecking((prev) => {
          const next = new Set(prev)
          next.delete(id)
          return next
        })
      })
    )
    await Promise.allSettled(promises)
    setSelected(new Set())
    tunnels.refetch()
  }

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

  async function handleDelete() {
    if (!deleteTarget) return
    await deleteMutation.mutateAsync(deleteTarget.id)
    setDeleteTarget(null)
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Tunnels</h1>
          <p className="text-sm text-muted-foreground">
            Manage VPN tunnel configurations.
          </p>
        </div>
        <RoleGuard requiredRole="operator">
          <Button asChild>
            <Link to="/tunnels/new">
              <Plus className="h-4 w-4" />
              Create Tunnel
            </Link>
          </Button>
        </RoleGuard>
      </div>

      {/* Search & Filters */}
      <div className="flex flex-wrap items-end gap-3">
        <div className="relative max-w-sm flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search tunnels..."
            value={search}
            onChange={(e) => {
              setSearch(e.target.value)
              goToPage(1)
            }}
            className="pl-9"
          />
        </div>
        <div className="w-[160px]">
          <Select
            value={statusFilter}
            onValueChange={(val) => {
              setStatusFilter(val)
              goToPage(1)
            }}
          >
            <SelectTrigger>
              <SelectValue placeholder="All statuses" />
            </SelectTrigger>
            <SelectContent>
              {STATUS_OPTIONS.map((opt) => (
                <SelectItem key={opt.value} value={opt.value}>
                  {opt.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      {/* Toolbar */}
      {selected.size > 0 && (
        <div className="flex items-center gap-3 rounded-lg border border-surface-border bg-surface px-4 py-2">
          <span className="text-sm text-muted-foreground">
            {selected.size} tunnel{selected.size > 1 ? 's' : ''} selected
          </span>
          <Button
            variant="outline"
            size="sm"
            disabled={checking.size > 0}
            onClick={handleCheckStatus}
          >
            <Activity className={checking.size > 0 ? 'h-4 w-4 animate-pulse' : 'h-4 w-4'} />
            {checking.size > 0 ? 'Checking...' : 'Check Status'}
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setSelected(new Set())}
          >
            Clear selection
          </Button>
        </div>
      )}

      {/* Table */}
      {tunnels.isLoading ? (
        <div className="space-y-3">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-12 w-full" />
          ))}
        </div>
      ) : tunnels.isError ? (
        <div className="rounded-lg border border-destructive/50 bg-destructive/10 p-4">
          <p className="text-sm text-destructive">
            Failed to load tunnels: {tunnels.error?.message ?? 'Unknown error'}
          </p>
          <button
            type="button"
            onClick={() => tunnels.refetch()}
            className="mt-2 text-xs text-muted-foreground hover:text-foreground transition-colors"
          >
            Retry
          </button>
        </div>
      ) : items.length === 0 ? (
        <EmptyState
          icon={Network}
          title="No tunnels configured yet"
          description="Create your first VPN tunnel to get started."
          action={
            <RoleGuard requiredRole="operator">
              <Button asChild variant="outline">
                <Link to="/tunnels/new">
                  <Plus className="h-4 w-4" />
                  Create Tunnel
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
                <TableHead className="w-10">
                  <input
                    type="checkbox"
                    className="h-4 w-4 rounded border-muted-foreground accent-primary"
                    checked={items.length > 0 && selected.size === items.length}
                    onChange={toggleSelectAll}
                  />
                </TableHead>
                <TableHead>Name</TableHead>
                <TableHead>Peer IP</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Sync</TableHead>
                <TableHead>Created</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((tunnel) => (
                <TableRow key={tunnel.id} className={checking.has(tunnel.id) ? 'opacity-60' : ''}>
                  <TableCell>
                    <input
                      type="checkbox"
                      className="h-4 w-4 rounded border-muted-foreground accent-primary"
                      checked={selected.has(tunnel.id)}
                      onChange={() => toggleSelected(tunnel.id)}
                    />
                  </TableCell>
                  <TableCell className="font-medium">
                    <Link
                      to={`/tunnels/${tunnel.id}`}
                      className="hover:text-primary transition-colors"
                    >
                      {tunnel.name}
                    </Link>
                  </TableCell>
                  <TableCell className="font-mono text-sm">{tunnel.peer_ip}</TableCell>
                  <TableCell>
                    <TunnelStatusCell tunnelId={tunnel.id} />
                  </TableCell>
                  <TableCell>
                    <SyncStatusCell syncStatus={tunnel.sync_status} syncError={tunnel.sync_error} />
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {new Date(tunnel.created_at).toLocaleDateString()}
                  </TableCell>
                  <TableCell className="text-right">
                    <div className="flex items-center justify-end gap-1">
                      <Button variant="ghost" size="icon" asChild>
                        <Link to={`/tunnels/${tunnel.id}`}>
                          <Eye className="h-4 w-4" />
                        </Link>
                      </Button>
                      <RoleGuard requiredRole="operator">
                        <Button variant="ghost" size="icon" asChild>
                          <Link to={`/tunnels/${tunnel.id}/edit`}>
                            <Pencil className="h-4 w-4" />
                          </Link>
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="text-muted-foreground hover:text-destructive"
                          onClick={() => setDeleteTarget(tunnel)}
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
              {Math.min(page * DEFAULT_PAGE_SIZE, tunnels.data.total)} of {tunnels.data.total} tunnels
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
        title="Delete Tunnel"
        description={`Are you sure you want to delete "${deleteTarget?.name}"? This will also remove all associated routes and iptables rules. This action cannot be undone.`}
        confirmLabel="Delete"
        variant="destructive"
        loading={deleteMutation.isPending}
        onConfirm={handleDelete}
      />
    </div>
  )
}
