import { useState } from 'react'
import { useServers } from '@/hooks/useServers'
import {
  useCaptures,
  useStartCapture,
  useCaptureOutput,
  useDeleteCapture,
} from '@/hooks/useCaptures'
import PermGuard from '@/components/shared/PermGuard'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Badge } from '@/components/ui/badge'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '@/components/ui/dialog'
import ConfirmDialog from '@/components/shared/ConfirmDialog'
import { formatDistanceToNow } from 'date-fns'

const INTERFACES = ['ens5', 'ens6', 'any']
const PROTOCOLS = ['all', 'tcp', 'udp', 'icmp']

function statusVariant(status) {
  if (status === 'completed') return 'default'
  if (status === 'running') return 'secondary'
  if (status === 'failed') return 'destructive'
  return 'outline'
}

function formatBytes(bytes) {
  if (!bytes) return '—'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`
}

export default function CapturesPage() {
  const { data: servers = [] } = useServers()
  const { data: captures = [], isLoading } = useCaptures()
  const startCapture = useStartCapture()
  const deleteCapture = useDeleteCapture()

  const [form, setForm] = useState({
    server_id: '',
    interface: 'ens5',
    duration_seconds: 60,
    mode: 'headers',
    host_filter: '',
    port_filter: '',
    protocol_filter: 'all',
  })
  const [viewCapture, setViewCapture] = useState(null)
  const [deleteTarget, setDeleteTarget] = useState(null)

  function handleStart(e) {
    e.preventDefault()
    const payload = {
      server_id: Number(form.server_id),
      interface: form.interface,
      duration_seconds: Number(form.duration_seconds),
      mode: form.mode,
      protocol_filter: form.protocol_filter,
    }
    if (form.host_filter) payload.host_filter = form.host_filter
    if (form.port_filter) payload.port_filter = Number(form.port_filter)
    startCapture.mutate(payload)
  }

  return (
    <div className="space-y-6 p-6">
      <h1 className="text-2xl font-semibold">Packet Captures</h1>

      {/* Start form — only for users with capture.headers */}
      <PermGuard permKey="capture.headers">
        <Card>
          <CardHeader>
            <CardTitle>Start Capture</CardTitle>
          </CardHeader>
          <CardContent>
            <form
              onSubmit={handleStart}
              className="grid grid-cols-2 gap-4 md:grid-cols-3"
            >
              <div className="space-y-1">
                <Label>Server</Label>
                <Select
                  value={form.server_id}
                  onValueChange={(v) =>
                    setForm((f) => ({ ...f, server_id: v }))
                  }
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Select server" />
                  </SelectTrigger>
                  <SelectContent>
                    {servers.map((s) => (
                      <SelectItem key={s.id} value={String(s.id)}>
                        {s.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-1">
                <Label>Interface</Label>
                <Select
                  value={form.interface}
                  onValueChange={(v) =>
                    setForm((f) => ({ ...f, interface: v }))
                  }
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {INTERFACES.map((i) => (
                      <SelectItem key={i} value={i}>
                        {i}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-1">
                <Label>Duration (seconds)</Label>
                <Input
                  type="number"
                  min={10}
                  max={300}
                  value={form.duration_seconds}
                  onChange={(e) =>
                    setForm((f) => ({ ...f, duration_seconds: e.target.value }))
                  }
                />
              </div>

              <div className="space-y-1">
                <Label>Mode</Label>
                <Select
                  value={form.mode}
                  onValueChange={(v) => setForm((f) => ({ ...f, mode: v }))}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="headers">Headers only</SelectItem>
                    <PermGuard permKey="capture.full">
                      <SelectItem value="full">Full payload (Tier 2)</SelectItem>
                    </PermGuard>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-1">
                <Label>Host filter (optional)</Label>
                <Input
                  placeholder="e.g. 10.0.0.1 or 10.0.0.0/24"
                  value={form.host_filter}
                  onChange={(e) =>
                    setForm((f) => ({ ...f, host_filter: e.target.value }))
                  }
                />
              </div>

              <div className="space-y-1">
                <Label>Port filter (optional)</Label>
                <Input
                  type="number"
                  placeholder="e.g. 443"
                  min={1}
                  max={65535}
                  value={form.port_filter}
                  onChange={(e) =>
                    setForm((f) => ({ ...f, port_filter: e.target.value }))
                  }
                />
              </div>

              <div className="space-y-1">
                <Label>Protocol</Label>
                <Select
                  value={form.protocol_filter}
                  onValueChange={(v) =>
                    setForm((f) => ({ ...f, protocol_filter: v }))
                  }
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {PROTOCOLS.map((p) => (
                      <SelectItem key={p} value={p}>
                        {p}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="col-span-full">
                <Button
                  type="submit"
                  disabled={!form.server_id || startCapture.isPending}
                >
                  {startCapture.isPending ? 'Starting…' : 'Start Capture'}
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      </PermGuard>

      {/* Captures list */}
      <Card>
        <CardHeader>
          <CardTitle>Captures</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : captures.length === 0 ? (
            <p className="text-sm text-muted-foreground">No captures yet.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>ID</TableHead>
                  <TableHead>Server</TableHead>
                  <TableHead>Mode</TableHead>
                  <TableHead>Interface</TableHead>
                  <TableHead>Duration</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Size</TableHead>
                  <TableHead>Started</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {captures.map((c) => (
                  <TableRow key={c.id}>
                    <TableCell className="font-mono">{c.id}</TableCell>
                    <TableCell>{c.server_id}</TableCell>
                    <TableCell>
                      <Badge variant="outline">{c.mode}</Badge>
                    </TableCell>
                    <TableCell className="font-mono">{c.interface}</TableCell>
                    <TableCell>{c.duration_seconds}s</TableCell>
                    <TableCell>
                      <Badge variant={statusVariant(c.status)}>
                        {c.status}
                      </Badge>
                    </TableCell>
                    <TableCell>{formatBytes(c.size_bytes)}</TableCell>
                    <TableCell>
                      {c.started_at
                        ? formatDistanceToNow(new Date(c.started_at), {
                            addSuffix: true,
                          })
                        : '—'}
                    </TableCell>
                    <TableCell>
                      <div className="flex gap-2">
                        {c.status === 'completed' && (
                          <PermGuard permKey="capture.headers">
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => setViewCapture(c)}
                            >
                              View
                            </Button>
                          </PermGuard>
                        )}
                        <Button
                          variant="ghost"
                          size="sm"
                          className="text-destructive hover:text-destructive"
                          onClick={() => setDeleteTarget(c)}
                        >
                          Delete
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* View output dialog */}
      {viewCapture && (
        <CaptureOutputDialog
          capture={viewCapture}
          onClose={() => setViewCapture(null)}
        />
      )}

      {/* Delete confirm */}
      <ConfirmDialog
        open={!!deleteTarget}
        title="Delete capture?"
        description={`This will remove capture #${deleteTarget?.id} and delete the pcap from S3. This cannot be undone.`}
        onConfirm={() => {
          deleteCapture.mutate(deleteTarget.id)
          setDeleteTarget(null)
        }}
        onCancel={() => setDeleteTarget(null)}
      />
    </div>
  )
}

function CaptureOutputDialog({ capture, onClose }) {
  const { data, isLoading, isError } = useCaptureOutput(capture.id)

  return (
    <Dialog open onOpenChange={onClose}>
      <DialogContent className="flex max-h-[80vh] max-w-4xl flex-col overflow-hidden">
        <DialogHeader>
          <DialogTitle>
            Capture #{capture.id} — {capture.mode} mode
          </DialogTitle>
        </DialogHeader>
        <div className="flex-1 overflow-auto">
          {isLoading && (
            <p className="text-sm text-muted-foreground">Loading…</p>
          )}
          {isError && (
            <p className="text-sm text-destructive">Failed to load output.</p>
          )}
          {data && (
            <>
              <div className="mb-2 flex items-center gap-2 text-xs text-muted-foreground">
                {data.truncated && (
                  <Badge variant="secondary">
                    Output truncated to 500 lines
                  </Badge>
                )}
                {data.payload_shown && (
                  <Badge variant="outline">Payload visible (Tier 2)</Badge>
                )}
              </div>
              <pre className="max-h-[50vh] overflow-auto whitespace-pre-wrap rounded bg-muted p-3 font-mono text-xs">
                {data.lines.join('\n') || '(no output)'}
              </pre>
            </>
          )}
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Close
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
