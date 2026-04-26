import { useState, useCallback } from 'react'
import { useSearchParams } from 'react-router-dom'
import { ChevronLeft, ChevronRight, FileText } from 'lucide-react'
import { useAuditLogs } from '@/hooks/useAuditLogs'
import AuditFilters from '@/components/audit/AuditFilters'
import EmptyState from '@/components/shared/EmptyState'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'

const PAGE_SIZE = 50

/** Map action verbs to badge variants. */
const ACTION_VARIANT = {
  create: 'success',
  update: 'default',
  delete: 'destructive',
  retry: 'warning',
  login: 'secondary',
}

/**
 * Format an ISO timestamp as a full date+time string for audit trail readability.
 * @param {string} isoString
 */
function formatTimestamp(isoString) {
  const d = new Date(isoString)
  return d.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

/**
 * Render a details cell. Shows a truncated summary of the change.
 * @param {{ previous_state: object|null, new_state: object|null }} entry
 */
function DetailsCell({ entry }) {
  const [expanded, setExpanded] = useState(false)

  const hasDetails = entry.previous_state || entry.new_state
  if (!hasDetails) return <span className="text-muted-foreground">-</span>

  const summary = entry.new_state
    ? JSON.stringify(entry.new_state)
    : JSON.stringify(entry.previous_state)

  if (!expanded && summary.length > 80) {
    return (
      <button
        type="button"
        className="text-left text-xs text-muted-foreground hover:text-foreground transition-colors"
        onClick={() => setExpanded(true)}
        title="Click to expand"
      >
        {summary.slice(0, 80)}&hellip;
      </button>
    )
  }

  return (
    <button
      type="button"
      className="text-left text-xs text-muted-foreground hover:text-foreground transition-colors break-all"
      onClick={() => setExpanded(false)}
    >
      {summary}
    </button>
  )
}

/**
 * Skeleton placeholder for the audit table while loading.
 */
function TableSkeleton() {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          {['Timestamp', 'User', 'Action', 'Entity Type', 'Entity ID', 'Details'].map((h) => (
            <TableHead key={h}>{h}</TableHead>
          ))}
        </TableRow>
      </TableHeader>
      <TableBody>
        {Array.from({ length: 10 }).map((_, i) => (
          <TableRow key={i}>
            {Array.from({ length: 6 }).map((__, j) => (
              <TableCell key={j}>
                <Skeleton className="h-4 w-full" />
              </TableCell>
            ))}
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}

function filtersFromParams(searchParams) {
  return {
    dateFrom: searchParams.get('dateFrom') ?? '',
    dateTo: searchParams.get('dateTo') ?? '',
    userId: searchParams.get('userId') ?? '',
    entityType: searchParams.get('entityType') ?? '',
    action: searchParams.get('action') ?? '',
  }
}

export default function AuditLogPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const [filters, setFilters] = useState(() => filtersFromParams(searchParams))

  const page = Number(searchParams.get('page')) || 1

  const { data, isLoading, isError, error } = useAuditLogs({
    page,
    pageSize: PAGE_SIZE,
    ...filters,
  })

  const totalPages = data ? Math.ceil(data.total / PAGE_SIZE) : 0

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

  const handleFiltersChange = useCallback((newFilters) => {
    setFilters(newFilters)
  }, [])

  const hasActiveFilters = ['dateFrom', 'dateTo', 'userId', 'entityType', 'action'].some(
    (k) => searchParams.get(k)
  )

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold">Audit Log</h1>
        <p className="text-sm text-muted-foreground">
          View system activity and change history.
        </p>
      </div>

      {/* Filters */}
      <AuditFilters onFiltersChange={handleFiltersChange} />

      {/* Error state */}
      {isError && (
        <div className="rounded-lg border border-destructive/30 bg-destructive/10 p-4 text-sm text-destructive">
          Failed to load audit logs: {error?.message ?? 'Unknown error'}
        </div>
      )}

      {/* Loading state */}
      {isLoading && <TableSkeleton />}

      {/* Empty state */}
      {!isLoading && !isError && data?.items?.length === 0 && (
        <EmptyState
          icon={FileText}
          title="No audit entries found"
          description={
            hasActiveFilters
              ? 'Try adjusting or clearing the active filters.'
              : 'System activity will appear here as users perform actions.'
          }
        />
      )}

      {/* Table */}
      {!isLoading && !isError && data?.items?.length > 0 && (
        <>
          <div className="rounded-lg border border-surface-border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[180px]">Timestamp</TableHead>
                  <TableHead className="w-[140px]">User</TableHead>
                  <TableHead className="w-[100px]">Action</TableHead>
                  <TableHead className="w-[120px]">Entity Type</TableHead>
                  <TableHead className="w-[90px]">Entity ID</TableHead>
                  <TableHead>Details</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.items.map((entry) => (
                  <TableRow key={entry.id}>
                    <TableCell className="text-xs whitespace-nowrap">
                      <time dateTime={entry.created_at}>
                        {formatTimestamp(entry.created_at)}
                      </time>
                    </TableCell>
                    <TableCell className="text-sm">
                      {entry.user?.display_name ?? entry.user?.email ?? 'System'}
                    </TableCell>
                    <TableCell>
                      <Badge variant={ACTION_VARIANT[entry.action] ?? 'outline'}>
                        {entry.action}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-sm capitalize">
                      {entry.entity_type?.replace(/_/g, ' ')}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {entry.entity_id != null ? `#${entry.entity_id}` : '-'}
                    </TableCell>
                    <TableCell>
                      <DetailsCell entry={entry} />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>

          {/* Pagination */}
          <div className="flex items-center justify-between">
            <p className="text-sm text-muted-foreground">
              Showing {(page - 1) * PAGE_SIZE + 1}
              &ndash;
              {Math.min(page * PAGE_SIZE, data.total)} of {data.total} entries
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
                disabled={!data.has_next}
                onClick={() => goToPage(page + 1)}
              >
                Next
                <ChevronRight className="h-4 w-4" />
              </Button>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
