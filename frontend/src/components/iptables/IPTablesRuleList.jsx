import { useState } from 'react'
import { Trash2, RotateCcw, Pencil, Shield } from 'lucide-react'
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
import EmptyState from '@/components/shared/EmptyState'
import { useIptablesRules, useDeleteIptablesRule, useRetryIptablesRule } from '@/hooks/useIptablesRules'
import IPTablesRuleForm from './IPTablesRuleForm'

const syncStatusConfig = {
  synced: { label: 'Applied', variant: 'success' },
  pending: { label: 'Pending', variant: 'warning' },
  failed: { label: 'Failed', variant: 'error' },
  pending_delete: { label: 'Deleting', variant: 'warning' },
}

function RuleSyncBadge({ status }) {
  const config = syncStatusConfig[status] ?? { label: status, variant: 'secondary' }
  return <Badge variant={config.variant}>{config.label}</Badge>
}

/**
 * Displays the iptables rules table for a tunnel with CRUD actions.
 *
 * @param {{ tunnelId: number|string }} props
 */
export default function IPTablesRuleList({ tunnelId }) {
  const rules = useIptablesRules(tunnelId)
  const deleteMutation = useDeleteIptablesRule(tunnelId)
  const retryMutation = useRetryIptablesRule(tunnelId)
  const [deleteTarget, setDeleteTarget] = useState(null)
  const [editTarget, setEditTarget] = useState(null)

  async function handleDelete() {
    if (!deleteTarget) return
    await deleteMutation.mutateAsync(deleteTarget.id)
    setDeleteTarget(null)
  }

  async function handleRetry(ruleId) {
    await retryMutation.mutateAsync(ruleId)
  }

  if (rules.isLoading) {
    return (
      <Card className="bg-surface border-surface-border">
        <CardHeader>
          <CardTitle>IPTables Rules</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <Skeleton className="h-8 w-full" />
          <Skeleton className="h-8 w-full" />
          <Skeleton className="h-8 w-full" />
        </CardContent>
      </Card>
    )
  }

  if (rules.isError) {
    return (
      <Card className="bg-surface border-surface-border">
        <CardContent className="py-6">
          <p className="text-sm text-destructive">
            Failed to load rules: {rules.error?.response?.data?.detail ?? rules.error?.message ?? 'Unknown error'}
          </p>
        </CardContent>
      </Card>
    )
  }

  const data = rules.data ?? []

  return (
    <Card className="bg-surface border-surface-border">
      <CardHeader className="flex flex-row items-center justify-between space-y-0">
        <CardTitle>IPTables Rules ({data.length})</CardTitle>
        <RoleGuard requiredRole="operator">
          {!editTarget && <IPTablesRuleForm tunnelId={tunnelId} />}
        </RoleGuard>
      </CardHeader>
      <CardContent>
        {editTarget && (
          <div className="mb-4">
            <IPTablesRuleForm
              tunnelId={tunnelId}
              editRule={editTarget}
              onClose={() => setEditTarget(null)}
            />
          </div>
        )}

        {data.length === 0 ? (
          <EmptyState
            icon={Shield}
            title="No firewall rules for this tunnel"
            description="Add iptables rules to control traffic flow through this tunnel."
          />
        ) : (
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Chain</TableHead>
                  <TableHead>Protocol</TableHead>
                  <TableHead>Source</TableHead>
                  <TableHead>Destination</TableHead>
                  <TableHead>Port</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Command</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.map((rule) => (
                  <TableRow key={rule.id}>
                    <TableCell className="font-mono text-xs">{rule.chain}</TableCell>
                    <TableCell className="text-sm">{rule.protocol}</TableCell>
                    <TableCell className="font-mono text-xs">
                      {rule.source_cidr ?? '-'}
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {rule.dest_cidr ?? '-'}
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {rule.dport ?? rule.sport ?? '-'}
                      {rule.sport && rule.dport ? ` (s:${rule.sport} d:${rule.dport})` : ''}
                    </TableCell>
                    <TableCell>
                      <Badge variant={rule.action === 'ACCEPT' ? 'success' : rule.action === 'DROP' ? 'error' : 'warning'}>
                        {rule.action}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <RuleSyncBadge status={rule.sync_status} />
                      {rule.sync_error && (
                        <p className="mt-1 max-w-xs truncate text-xs text-destructive" title={rule.sync_error}>
                          {rule.sync_error}
                        </p>
                      )}
                    </TableCell>
                    <TableCell className="max-w-[200px]">
                      {rule.command_preview && (
                        <code className="block truncate font-mono text-xs text-muted-foreground" title={rule.command_preview}>
                          {rule.command_preview}
                        </code>
                      )}
                    </TableCell>
                    <TableCell className="text-right">
                      <RoleGuard requiredRole="operator">
                        <div className="flex items-center justify-end gap-1">
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => setEditTarget(rule)}
                            disabled={editTarget?.id === rule.id}
                            title="Edit"
                          >
                            <Pencil className="h-4 w-4" />
                          </Button>
                          {rule.sync_status === 'failed' && (
                            <Button
                              variant="ghost"
                              size="icon"
                              onClick={() => handleRetry(rule.id)}
                              disabled={retryMutation.isPending}
                              title="Retry"
                            >
                              <RotateCcw className="h-4 w-4" />
                            </Button>
                          )}
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => setDeleteTarget(rule)}
                            disabled={deleteMutation.isPending || rule.sync_status === 'pending_delete'}
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
          </div>
        )}
      </CardContent>

      <ConfirmDialog
        open={!!deleteTarget}
        onOpenChange={(open) => { if (!open) setDeleteTarget(null) }}
        title="Delete IPTables Rule"
        description={`Are you sure you want to delete this ${deleteTarget?.chain} rule (${deleteTarget?.action} ${deleteTarget?.protocol})? This will remove the rule from the system.`}
        confirmLabel="Delete"
        variant="destructive"
        loading={deleteMutation.isPending}
        onConfirm={handleDelete}
      />
    </Card>
  )
}
