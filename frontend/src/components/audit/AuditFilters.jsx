import { useState, useEffect } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Filter, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useAuth } from '@/hooks/useAuth'
import { useUsers } from '@/hooks/useUsers'

const ALL = '__all__'
const NO_USER = '__none__'

const ENTITY_TYPES = [
  { value: ALL, label: 'All types' },
  { value: 'tunnel', label: 'Tunnel' },
  { value: 'route', label: 'Route' },
  { value: 'iptables_rule', label: 'IPTables Rule' },
  { value: 'user', label: 'User' },
]

const ACTIONS = [
  { value: ALL, label: 'All actions' },
  { value: 'create', label: 'Create' },
  { value: 'update', label: 'Update' },
  { value: 'delete', label: 'Delete' },
  { value: 'retry', label: 'Retry' },
  { value: 'login', label: 'Login' },
]

/** Filter param keys we manage. */
const FILTER_KEYS = ['dateFrom', 'dateTo', 'userId', 'entityType', 'action']

/**
 * Read current filters from URL search params.
 * @param {URLSearchParams} searchParams
 */
function filtersFromParams(searchParams) {
  return {
    dateFrom: searchParams.get('dateFrom') ?? '',
    dateTo: searchParams.get('dateTo') ?? '',
    userId: searchParams.get('userId') ?? '',
    entityType: searchParams.get('entityType') ?? '',
    action: searchParams.get('action') ?? '',
  }
}

/**
 * Audit log filter controls. Persists filter state in URL query params
 * so bookmarking / sharing filtered views works out of the box.
 *
 * @param {{ onFiltersChange: (filters: object) => void }} props
 */
export default function AuditFilters({ onFiltersChange }) {
  const { role } = useAuth()
  const isAdmin = role === 'admin'
  const usersQuery = useUsers({ page: 1, pageSize: 200 })
  const userList = usersQuery.data?.items ?? []
  const [searchParams, setSearchParams] = useSearchParams()

  // Local form state — initialized from URL on mount / URL change
  const [form, setForm] = useState(() => filtersFromParams(searchParams))

  // Sync URL → form when URL changes externally (e.g. browser back)
  useEffect(() => {
    setForm(filtersFromParams(searchParams))
  }, [searchParams])

  // Notify parent whenever URL params change
  useEffect(() => {
    onFiltersChange(filtersFromParams(searchParams))
  }, [searchParams, onFiltersChange])

  const updateField = (key, value) => {
    setForm((prev) => ({ ...prev, [key]: value }))
  }

  const applyFilters = () => {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev)
      // Reset to page 1 when filters change
      next.delete('page')
      FILTER_KEYS.forEach((key) => {
        if (form[key]) {
          next.set(key, form[key])
        } else {
          next.delete(key)
        }
      })
      return next
    })
  }

  const clearFilters = () => {
    const empty = { dateFrom: '', dateTo: '', userId: '', entityType: '', action: '' }
    setForm(empty)
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev)
      next.delete('page')
      FILTER_KEYS.forEach((key) => next.delete(key))
      return next
    })
  }

  const hasActiveFilters = FILTER_KEYS.some((key) => searchParams.get(key))

  const handleKeyDown = (e) => {
    if (e.key === 'Enter') applyFilters()
  }

  return (
    <div className="rounded-lg border border-surface-border bg-surface p-4 space-y-4">
      <div className="flex items-center gap-2 text-sm font-medium text-muted-foreground">
        <Filter className="h-4 w-4" />
        Filters
        {hasActiveFilters && (
          <span className="ml-1 rounded-full bg-primary/10 px-2 py-0.5 text-xs text-primary">
            Active
          </span>
        )}
      </div>

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-5">
        {/* Date From */}
        <div className="space-y-1">
          <label htmlFor="audit-date-from" className="text-xs text-muted-foreground">
            From date
          </label>
          <Input
            id="audit-date-from"
            type="date"
            value={form.dateFrom}
            onChange={(e) => updateField('dateFrom', e.target.value)}
            onKeyDown={handleKeyDown}
          />
        </div>

        {/* Date To */}
        <div className="space-y-1">
          <label htmlFor="audit-date-to" className="text-xs text-muted-foreground">
            To date
          </label>
          <Input
            id="audit-date-to"
            type="date"
            value={form.dateTo}
            onChange={(e) => updateField('dateTo', e.target.value)}
            onKeyDown={handleKeyDown}
          />
        </div>

        {/* User */}
        <div className="space-y-1">
          <label htmlFor="audit-user" className="text-xs text-muted-foreground">
            User
          </label>
          {isAdmin && userList.length > 0 ? (
            <Select
              value={form.userId || NO_USER}
              onValueChange={(val) => updateField('userId', val === NO_USER ? '' : val)}
            >
              <SelectTrigger>
                <SelectValue placeholder="All users" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={NO_USER}>All users</SelectItem>
                {userList.map((u) => (
                  <SelectItem key={u.id} value={String(u.id)}>
                    {u.display_name || u.email}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          ) : (
            <Input
              id="audit-user"
              type="text"
              placeholder="User ID (e.g. 1)"
              value={form.userId}
              onChange={(e) => updateField('userId', e.target.value)}
              onKeyDown={handleKeyDown}
            />
          )}
        </div>

        {/* Entity Type */}
        <div className="space-y-1">
          <label className="text-xs text-muted-foreground">Entity type</label>
          <Select
            value={form.entityType || ALL}
            onValueChange={(val) => updateField('entityType', val === ALL ? '' : val)}
          >
            <SelectTrigger>
              <SelectValue placeholder="All types" />
            </SelectTrigger>
            <SelectContent>
              {ENTITY_TYPES.map((opt) => (
                <SelectItem key={opt.value} value={opt.value}>
                  {opt.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        {/* Action */}
        <div className="space-y-1">
          <label className="text-xs text-muted-foreground">Action</label>
          <Select
            value={form.action || ALL}
            onValueChange={(val) => updateField('action', val === ALL ? '' : val)}
          >
            <SelectTrigger>
              <SelectValue placeholder="All actions" />
            </SelectTrigger>
            <SelectContent>
              {ACTIONS.map((opt) => (
                <SelectItem key={opt.value} value={opt.value}>
                  {opt.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      <div className="flex items-center gap-2">
        <Button size="sm" onClick={applyFilters}>
          Apply Filters
        </Button>
        {hasActiveFilters && (
          <Button size="sm" variant="ghost" onClick={clearFilters}>
            <X className="h-3.5 w-3.5" />
            Clear
          </Button>
        )}
      </div>
    </div>
  )
}
