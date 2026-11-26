import { useState } from 'react'
import { Users } from 'lucide-react'
import { useAuth } from '@/hooks/useAuth'
import { useUsers, useUpdateUser, useRevokeUserSessions } from '@/hooks/useUsers'
import { useUserPermissions, useSetUserPermissions } from '@/hooks/usePermissions'
import ConfirmDialog from '@/components/shared/ConfirmDialog'
import EmptyState from '@/components/shared/EmptyState'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
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
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip'

const TIER1_KEYS = [
  'tunnels.write',
  'tunnels.connect',
  'tunnels.psk',
  'routes.write',
  'iptables.filter',
  'iptables.snat',
]

/**
 * Dialog for editing a single operator user's Tier 1 permissions and Shortcut member ID.
 */
function PermissionsDialog({ user, open, onOpenChange }) {
  const permsQuery = useUserPermissions(user?.id, { enabled: open })
  const setPerms = useSetUserPermissions()
  const updateUser = useUpdateUser()

  // Local state mirrors the loaded permissions once available
  const [checkedKeys, setCheckedKeys] = useState(null)
  const [shortcutId, setShortcutId] = useState(null)

  // Sync local state when query data arrives (and dialog opens fresh)
  const loaded = permsQuery.data
  if (loaded && checkedKeys === null) {
    setCheckedKeys(new Set(loaded.permissions ?? []))
  }
  if (user && shortcutId === null) {
    setShortcutId(user.shortcut_member_id ?? '')
  }

  function handleOpenChange(next) {
    if (!next) {
      // Reset local state so next open starts fresh
      setCheckedKeys(null)
      setShortcutId(null)
    }
    onOpenChange(next)
  }

  function toggleKey(key) {
    setCheckedKeys((prev) => {
      const next = new Set(prev)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })
  }

  async function handleSave() {
    const userId = user.id
    const permsSave = setPerms.mutateAsync({ userId, permissions: [...(checkedKeys ?? [])] })
    const idChanged = shortcutId !== (user.shortcut_member_id ?? '')
    const idSave = idChanged
      ? updateUser.mutateAsync({ id: userId, data: { shortcut_member_id: shortcutId || null } })
      : Promise.resolve()
    await Promise.all([permsSave, idSave])
    handleOpenChange(false)
  }

  const isSaving = setPerms.isPending || updateUser.isPending

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="max-w-sm">
        <DialogHeader>
          <DialogTitle>Permissions — {user?.display_name || user?.email}</DialogTitle>
        </DialogHeader>

        {permsQuery.isLoading && (
          <div className="space-y-2 py-2">
            {[...Array(6)].map((_, i) => <Skeleton key={i} className="h-5 w-full" />)}
          </div>
        )}

        {!permsQuery.isLoading && (
          <div className="space-y-4 py-1">
            {/* Tier 1 checkboxes */}
            <div className="space-y-2">
              <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
                Tier 1 Permissions
              </p>
              {TIER1_KEYS.map((key) => (
                <label
                  key={key}
                  className="flex items-center gap-2 cursor-pointer select-none"
                >
                  <input
                    type="checkbox"
                    className="h-4 w-4 rounded border-input"
                    checked={checkedKeys?.has(key) ?? false}
                    onChange={() => toggleKey(key)}
                  />
                  <span className="text-sm font-mono">{key}</span>
                </label>
              ))}
            </div>

            {/* Shortcut member ID */}
            <div className="space-y-1.5">
              <Label htmlFor="shortcut-member-id">Shortcut Member ID</Label>
              <Input
                id="shortcut-member-id"
                placeholder="e.g. 5d4a3b2c1e0f..."
                value={shortcutId ?? ''}
                onChange={(e) => setShortcutId(e.target.value)}
              />
              <p className="text-xs text-muted-foreground">
                Required to link Tier 2 access requests to this user's Shortcut account.
              </p>
            </div>
          </div>
        )}

        <DialogFooter>
          <Button variant="outline" onClick={() => handleOpenChange(false)} disabled={isSaving}>
            Cancel
          </Button>
          <Button onClick={handleSave} disabled={isSaving || permsQuery.isLoading}>
            {isSaving ? 'Saving…' : 'Save'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

const ROLES = ['admin', 'operator', 'viewer']

/** Badge variant per role. */
const ROLE_VARIANT = {
  admin: 'default',
  operator: 'warning',
  viewer: 'secondary',
}

/**
 * Format an ISO timestamp for display, or return a dash if null.
 * @param {string|null} isoString
 */
function formatDate(isoString) {
  if (!isoString) return '-'
  return new Date(isoString).toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  })
}

/** Skeleton placeholder rows while loading. */
function TableSkeleton() {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          {['Name', 'Email', 'Role', 'Status', 'Last Login', 'Actions'].map((h) => (
            <TableHead key={h}>{h}</TableHead>
          ))}
        </TableRow>
      </TableHeader>
      <TableBody>
        {Array.from({ length: 8 }).map((_, i) => (
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

export default function UserManagementPage() {
  const { user: currentUser } = useAuth()
  const { data, isLoading, isError, error } = useUsers()
  const updateUser = useUpdateUser()
  const revokeUserSessions = useRevokeUserSessions()

  // Confirmation dialog state
  const [confirmDialog, setConfirmDialog] = useState({
    open: false,
    title: '',
    description: '',
    variant: 'default',
    onConfirm: () => {},
  })

  // Permissions dialog state
  const [permDialogUser, setPermDialogUser] = useState(null)

  const isSelf = (userId) => currentUser?.id === userId

  /**
   * Handle role change — opens confirmation dialog first.
   */
  function handleRoleChange(user, newRole) {
    if (newRole === user.role) return

    setConfirmDialog({
      open: true,
      title: 'Change User Role',
      description: `Are you sure you want to change ${user.display_name || user.email}'s role from "${user.role}" to "${newRole}"?`,
      variant: 'default',
      onConfirm: () => {
        setConfirmDialog((prev) => ({ ...prev, open: false }))
        updateUser.mutate({ id: user.id, data: { role: newRole } })
      },
    })
  }

  /**
   * Handle revoke sessions — opens confirmation dialog first.
   */
  function handleRevokeSessions(user) {
    setConfirmDialog({
      open: true,
      title: 'Revoke Sessions',
      description: `This will sign out ${user.display_name || user.email} from all devices immediately. They can log in again to get a new session.`,
      variant: 'destructive',
      onConfirm: () => {
        setConfirmDialog((prev) => ({ ...prev, open: false }))
        revokeUserSessions.mutate({ id: user.id })
      },
    })
  }

  /**
   * Handle active/inactive toggle — opens confirmation dialog first.
   */
  function handleToggleActive(user) {
    const newActive = !user.is_active
    const action = newActive ? 'activate' : 'deactivate'

    setConfirmDialog({
      open: true,
      title: `${newActive ? 'Activate' : 'Deactivate'} User`,
      description: `Are you sure you want to ${action} ${user.display_name || user.email}?`,
      variant: newActive ? 'default' : 'destructive',
      onConfirm: () => {
        setConfirmDialog((prev) => ({ ...prev, open: false }))
        updateUser.mutate({ id: user.id, data: { is_active: newActive } })
      },
    })
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold">User Management</h1>
        <p className="text-sm text-muted-foreground">
          Manage user roles and access. Changes take effect immediately.
        </p>
      </div>

      {/* Error state */}
      {isError && (
        <div className="rounded-lg border border-destructive/30 bg-destructive/10 p-4 text-sm text-destructive">
          Failed to load users: {error?.message ?? 'Unknown error'}
        </div>
      )}

      {/* Loading state */}
      {isLoading && <TableSkeleton />}

      {/* Empty state */}
      {!isLoading && !isError && data?.items?.length === 0 && (
        <EmptyState
          icon={Users}
          title="No users found"
          description="Users will appear here once they log in via SSO."
        />
      )}

      {/* Users table */}
      {!isLoading && !isError && data?.items?.length > 0 && (
        <TooltipProvider>
          <div className="rounded-lg border border-surface-border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[180px]">Name</TableHead>
                  <TableHead className="w-[220px]">Email</TableHead>
                  <TableHead className="w-[150px]">Role</TableHead>
                  <TableHead className="w-[100px]">Status</TableHead>
                  <TableHead className="w-[160px]">Last Login</TableHead>
                  <TableHead className="w-[260px]">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.items.map((user) => {
                  const self = isSelf(user.id)

                  return (
                    <TableRow
                      key={user.id}
                      className={self ? 'bg-muted/40' : undefined}
                    >
                      {/* Name */}
                      <TableCell className="text-sm font-medium">
                        {user.display_name || '-'}
                        {self && (
                          <span className="ml-2 text-xs text-muted-foreground">(you)</span>
                        )}
                      </TableCell>

                      {/* Email */}
                      <TableCell className="text-sm">{user.email}</TableCell>

                      {/* Role — inline select or badge */}
                      <TableCell>
                        {self ? (
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <div>
                                <Badge variant={ROLE_VARIANT[user.role] ?? 'outline'}>
                                  {user.role}
                                </Badge>
                              </div>
                            </TooltipTrigger>
                            <TooltipContent>
                              You cannot change your own role
                            </TooltipContent>
                          </Tooltip>
                        ) : (
                          <Select
                            value={user.role}
                            onValueChange={(value) => handleRoleChange(user, value)}
                          >
                            <SelectTrigger className="h-8 w-[120px]">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              {ROLES.map((role) => (
                                <SelectItem key={role} value={role}>
                                  {role}
                                </SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                        )}
                      </TableCell>

                      {/* Status */}
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <span
                            className={`inline-block h-2 w-2 rounded-full ${
                              user.is_active ? 'bg-success' : 'bg-destructive'
                            }`}
                          />
                          <span className="text-sm">
                            {user.is_active ? 'Active' : 'Inactive'}
                          </span>
                        </div>
                      </TableCell>

                      {/* Last Login */}
                      <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                        {formatDate(user.last_login_at)}
                      </TableCell>

                      {/* Actions */}
                      <TableCell>
                        <div className="flex items-center gap-2">
                          {self ? (
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <div>
                                  <Button variant="outline" size="sm" disabled>
                                    {user.is_active ? 'Deactivate' : 'Activate'}
                                  </Button>
                                </div>
                              </TooltipTrigger>
                              <TooltipContent>
                                You cannot deactivate your own account
                              </TooltipContent>
                            </Tooltip>
                          ) : (
                            <>
                              <Button
                                variant={user.is_active ? 'outline' : 'default'}
                                size="sm"
                                onClick={() => handleToggleActive(user)}
                                disabled={updateUser.isPending}
                              >
                                {user.is_active ? 'Deactivate' : 'Activate'}
                              </Button>
                              <Button
                                variant="outline"
                                size="sm"
                                onClick={() => handleRevokeSessions(user)}
                                disabled={revokeUserSessions.isPending}
                              >
                                Revoke sessions
                              </Button>
                            </>
                          )}
                          {user.role === 'operator' && (
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => setPermDialogUser(user)}
                            >
                              Permissions
                            </Button>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          </div>

          {/* Total count */}
          <p className="text-sm text-muted-foreground">
            {data.total} user{data.total !== 1 ? 's' : ''} total
          </p>
        </TooltipProvider>
      )}

      {/* Confirmation dialog */}
      <ConfirmDialog
        open={confirmDialog.open}
        onOpenChange={(open) => setConfirmDialog((prev) => ({ ...prev, open }))}
        title={confirmDialog.title}
        description={confirmDialog.description}
        variant={confirmDialog.variant}
        onConfirm={confirmDialog.onConfirm}
        loading={updateUser.isPending}
      />

      {/* Permissions dialog */}
      {permDialogUser && (
        <PermissionsDialog
          user={permDialogUser}
          open={!!permDialogUser}
          onOpenChange={(open) => { if (!open) setPermDialogUser(null) }}
        />
      )}
    </div>
  )
}
