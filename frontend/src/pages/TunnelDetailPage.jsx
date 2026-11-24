import { useState } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import { ArrowLeft, Copy, Eye, EyeOff, Key, Pencil, RefreshCw, Trash2 } from 'lucide-react'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import RoleGuard from '@/components/shared/RoleGuard'
import ConfirmDialog from '@/components/shared/ConfirmDialog'
import TunnelStatusCell from '@/components/tunnels/TunnelStatusCell'
import RouteList from '@/components/routes/RouteList'
import IPTablesRuleList from '@/components/iptables/IPTablesRuleList'
import { useTunnel, useDeleteTunnel, useRetryTunnelSync, useRotateTunnelPsk, useAllTunnelsLiveStatus } from '@/hooks/useTunnels'
import { useRoutes } from '@/hooks/useRoutes'
import { useIptablesRules } from '@/hooks/useIptablesRules'

function InfoField({ label, children }) {
  return (
    <div className="space-y-1">
      <dt className="text-sm font-medium text-muted-foreground">{label}</dt>
      <dd className="text-sm">{children}</dd>
    </div>
  )
}

function InfoTab({ tunnel }) {
  return (
    <Card className="bg-surface border-surface-border">
      <CardHeader>
        <CardTitle>Tunnel Information</CardTitle>
      </CardHeader>
      <CardContent>
        <dl className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <InfoField label="Name">{tunnel.name}</InfoField>
          <InfoField label="Peer IP">
            <span className="font-mono">{tunnel.peer_ip}</span>
          </InfoField>
          <InfoField label="IKE Version">v{tunnel.ike_version}</InfoField>
          <InfoField label="Status">{tunnel.status}</InfoField>
          <InfoField label="Sync Status">
            <span className={
              tunnel.sync_status === 'synced' ? 'text-success' :
              tunnel.sync_status === 'failed' ? 'text-destructive' :
              tunnel.sync_status === 'pending' ? 'text-warning' : ''
            }>
              {tunnel.sync_status}
            </span>
          </InfoField>
          {tunnel.sync_error && (
            <div className="sm:col-span-2">
              <InfoField label="Sync Details">
                <pre className="whitespace-pre-wrap break-words text-xs font-mono rounded-md bg-surface-hover p-3 border border-surface-border text-destructive">
                  {tunnel.sync_error}
                </pre>
              </InfoField>
            </div>
          )}
          <InfoField label="DPD Action">{tunnel.dpd_action}</InfoField>
          <InfoField label="DPD Delay">{tunnel.dpd_delay}s</InfoField>
          <InfoField label="DPD Timeout">{tunnel.dpd_timeout}s</InfoField>
          {tunnel.ike_proposals && (
            <InfoField label="IKE Proposals">
              <span className="font-mono text-xs">{tunnel.ike_proposals}</span>
            </InfoField>
          )}
          {tunnel.esp_proposals && (
            <InfoField label="ESP Proposals">
              <span className="font-mono text-xs">{tunnel.esp_proposals}</span>
            </InfoField>
          )}
          <InfoField label="Local CIDRs">
            <ul className="space-y-0.5">
              {tunnel.local_cidrs.map((cidr) => (
                <li key={cidr} className="font-mono text-xs">{cidr}</li>
              ))}
            </ul>
          </InfoField>
          <InfoField label="Remote CIDRs">
            <ul className="space-y-0.5">
              {tunnel.remote_cidrs.map((cidr) => (
                <li key={cidr} className="font-mono text-xs">{cidr}</li>
              ))}
            </ul>
          </InfoField>
          {tunnel.description && (
            <div className="sm:col-span-2">
              <InfoField label="Description">{tunnel.description}</InfoField>
            </div>
          )}
          <InfoField label="Created">
            {new Date(tunnel.created_at).toLocaleString()}
          </InfoField>
          <InfoField label="Updated">
            {new Date(tunnel.updated_at).toLocaleString()}
          </InfoField>
          <InfoField label="PSK Last Rotated">
            {tunnel.psk_rotated_at ? new Date(tunnel.psk_rotated_at).toLocaleString() : 'Never'}
          </InfoField>
          {tunnel.creator && (
            <InfoField label="Created By">{tunnel.creator.email ?? tunnel.creator.name}</InfoField>
          )}
        </dl>
      </CardContent>
    </Card>
  )
}

function RoutesTab({ tunnelId, remoteCidrs }) {
  return <RouteList tunnelId={tunnelId} remoteCidrs={remoteCidrs} />
}

function IPTablesTab({ tunnelId }) {
  return <IPTablesRuleList tunnelId={tunnelId} />
}

export default function TunnelDetailPage() {
  const { id } = useParams()
  const navigate = useNavigate()
  const [showDelete, setShowDelete] = useState(false)
  const [showRotateConfirm, setShowRotateConfirm] = useState(false)
  const [useCustomPsk, setUseCustomPsk] = useState(false)
  const [customPsk, setCustomPsk] = useState('')
  const [revealedPsk, setRevealedPsk] = useState(null)
  const [rotateResult, setRotateResult] = useState(null)
  const [showPsk, setShowPsk] = useState(false)
  const tunnel = useTunnel(id)
  const routes = useRoutes(Number(id))
  const iptablesRules = useIptablesRules(Number(id))
  const liveStatus = useAllTunnelsLiveStatus()
  const deleteMutation = useDeleteTunnel()
  const retrySync = useRetryTunnelSync()
  const rotateMutation = useRotateTunnelPsk()

  async function handleDelete() {
    await deleteMutation.mutateAsync(Number(id))
    navigate('/tunnels')
  }

  function handleRotateConfirm() {
    rotateMutation.mutate(
      { tunnelId: Number(id), psk: useCustomPsk ? customPsk : undefined },
      {
        onSuccess: (data) => {
          setRevealedPsk(data.psk)
          setRotateResult({ sync_status: data.sync_status, sync_details: data.sync_details })
          setShowRotateConfirm(false)
          setUseCustomPsk(false)
          setCustomPsk('')
        },
      }
    )
  }

  function handleRevealClose() {
    setRevealedPsk(null)
    setRotateResult(null)
    setShowPsk(false)
    rotateMutation.reset()
  }

  function handleCopyPsk() {
    if (revealedPsk) {
      navigator.clipboard.writeText(revealedPsk).catch(() => {})
    }
  }

  if (tunnel.isLoading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-4 w-96" />
        <Skeleton className="h-64 w-full" />
      </div>
    )
  }

  if (tunnel.isError) {
    return (
      <div className="space-y-4">
        <Button variant="ghost" onClick={() => navigate('/tunnels')}>
          <ArrowLeft className="h-4 w-4" />
          Back to Tunnels
        </Button>
        <div className="rounded-lg border border-destructive/50 bg-destructive/10 p-4">
          <p className="text-sm text-destructive">
            Failed to load tunnel: {tunnel.error?.response?.data?.detail ?? tunnel.error?.message ?? 'Unknown error'}
          </p>
        </div>
      </div>
    )
  }

  const data = tunnel.data
  const liveRow = liveStatus.data?.tunnels?.find((r) => r.tunnel_id === data.id)

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="space-y-1">
          <div className="flex items-center gap-3">
            <Button variant="ghost" size="icon" asChild>
              <Link to="/tunnels">
                <ArrowLeft className="h-4 w-4" />
              </Link>
            </Button>
            <h1 className="text-2xl font-bold">{data.name}</h1>
            <TunnelStatusCell
              liveRow={liveRow}
              isLoading={liveStatus.isLoading}
              isError={liveStatus.isError}
            />
            {data.sync_status === 'failed' && (
              <RoleGuard requiredRole="operator">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={retrySync.isPending}
                  onClick={() => retrySync.mutate(Number(id))}
                >
                  <RefreshCw className={cn('h-4 w-4', retrySync.isPending && 'animate-spin')} />
                  Retry Sync
                </Button>
              </RoleGuard>
            )}
          </div>
          {data.description && (
            <p className="ml-12 text-sm text-muted-foreground">{data.description}</p>
          )}
        </div>
        <RoleGuard requiredRole="operator">
          <div className="flex items-center gap-2">
            <Button variant="outline" asChild>
              <Link to={`/tunnels/${id}/edit`}>
                <Pencil className="h-4 w-4" />
                Edit
              </Link>
            </Button>
            <Button variant="outline" onClick={() => setShowRotateConfirm(true)}>
              <Key className="h-4 w-4" />
              Rotate PSK
            </Button>
            <Button variant="destructive" onClick={() => setShowDelete(true)}>
              <Trash2 className="h-4 w-4" />
              Delete
            </Button>
          </div>
        </RoleGuard>
      </div>

      {/* Tabs */}
      <Tabs defaultValue="info">
        <TabsList>
          <TabsTrigger value="info">Info</TabsTrigger>
          <TabsTrigger value="routes">
            Routes ({routes.data?.length ?? 0})
          </TabsTrigger>
          <TabsTrigger value="iptables">
            IPTables ({iptablesRules.data?.length ?? 0})
          </TabsTrigger>
        </TabsList>
        <TabsContent value="info">
          <InfoTab tunnel={data} />
        </TabsContent>
        <TabsContent value="routes">
          <RoutesTab tunnelId={data.id} remoteCidrs={data.remote_cidrs} />
        </TabsContent>
        <TabsContent value="iptables">
          <IPTablesTab tunnelId={data.id} />
        </TabsContent>
      </Tabs>

      {/* Delete confirmation */}
      <ConfirmDialog
        open={showDelete}
        onOpenChange={setShowDelete}
        title="Delete Tunnel"
        description={`Are you sure you want to delete "${data.name}"? This will also remove all associated routes and iptables rules. This action cannot be undone.`}
        confirmLabel="Delete"
        variant="destructive"
        loading={deleteMutation.isPending}
        onConfirm={handleDelete}
      />

      {/* Rotate PSK — confirm */}
      <Dialog
        open={showRotateConfirm}
        onOpenChange={(open) => {
          if (!open) {
            setShowRotateConfirm(false)
            setUseCustomPsk(false)
            setCustomPsk('')
          }
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Rotate PSK</DialogTitle>
            <DialogDescription>
              The remote peer must be updated with the new PSK immediately or the tunnel will drop.
              By default a new PSK is generated server-side.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3 py-1">
            <div className="flex items-center gap-2">
              <input
                id="use-custom-psk"
                type="checkbox"
                className="h-4 w-4 cursor-pointer"
                checked={useCustomPsk}
                onChange={(e) => { setUseCustomPsk(e.target.checked); setCustomPsk('') }}
              />
              <label htmlFor="use-custom-psk" className="text-sm cursor-pointer select-none">
                Use a custom PSK
              </label>
            </div>
            {useCustomPsk && (
              <Input
                type="text"
                placeholder="Enter custom PSK (min 1 character)"
                value={customPsk}
                onChange={(e) => setCustomPsk(e.target.value)}
                autoComplete="off"
                autoCapitalize="none"
                spellCheck={false}
              />
            )}
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              disabled={rotateMutation.isPending}
              onClick={() => { setShowRotateConfirm(false); setUseCustomPsk(false); setCustomPsk('') }}
            >
              Cancel
            </Button>
            <Button
              disabled={rotateMutation.isPending || (useCustomPsk && !customPsk.trim())}
              onClick={handleRotateConfirm}
            >
              {rotateMutation.isPending ? 'Rotating…' : 'Rotate PSK'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Rotate PSK — reveal (shown once) */}
      <Dialog
        open={revealedPsk !== null}
        onOpenChange={(open) => { if (!open) handleRevealClose() }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>New PSK — Save Now</DialogTitle>
            <DialogDescription>
              This PSK will not be shown again. Copy it and update your remote peer immediately.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            {rotateResult?.sync_status && rotateResult.sync_status !== 'synced' && (
              <div className="rounded-md border border-warning/50 bg-warning/10 p-3 text-sm text-warning">
                Sync status: <strong>{rotateResult.sync_status}</strong> — some nodes may not have
                the new PSK yet. The reconciler will retry automatically.
                {rotateResult.sync_details && (
                  <pre className="mt-1 text-xs font-mono whitespace-pre-wrap break-all opacity-80">
                    {JSON.stringify(rotateResult.sync_details, null, 2)}
                  </pre>
                )}
              </div>
            )}
            <div className="flex items-center gap-2">
              <Input
                type={showPsk ? 'text' : 'password'}
                value={revealedPsk ?? ''}
                readOnly
                className="font-mono text-sm"
                autoComplete="off"
              />
              <Button
                variant="ghost"
                size="icon"
                aria-label={showPsk ? 'Hide PSK' : 'Show PSK'}
                onClick={() => setShowPsk((v) => !v)}
              >
                {showPsk ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </Button>
              <Button
                variant="ghost"
                size="icon"
                aria-label="Copy PSK to clipboard"
                onClick={handleCopyPsk}
              >
                <Copy className="h-4 w-4" />
              </Button>
            </div>
          </div>
          <DialogFooter>
            <Button onClick={handleRevealClose}>Close</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
