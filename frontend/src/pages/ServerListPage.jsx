import { useState } from 'react'
import { Link, useSearchParams, useNavigate } from 'react-router-dom'
import { Plus, Pencil, Trash2, Search, Server, ChevronLeft, ChevronRight, CheckCircle2, XCircle, Clock, Plug } from 'lucide-react'
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
import RoleGuard from '@/components/shared/RoleGuard'
import ConfirmDialog from '@/components/shared/ConfirmDialog'
import EmptyState from '@/components/shared/EmptyState'
import { useServers, useDeleteServer, useTestConnection } from '@/hooks/useServers'
import { DEFAULT_PAGE_SIZE } from '@/lib/constants'

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
            Manage SSH server connections.
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
          description="Add your first SSH server to get started."
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
                <TableHead>Hostname</TableHead>
                <TableHead>Port</TableHead>
                <TableHead>User</TableHead>
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
                  <TableCell className="font-mono text-sm">{server.hostname}</TableCell>
                  <TableCell className="text-sm">{server.ssh_port}</TableCell>
                  <TableCell className="text-sm">{server.ssh_user}</TableCell>
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
    </div>
  )
}
