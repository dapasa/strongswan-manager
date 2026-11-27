import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { ExternalLink, ShieldCheck, Clock } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Textarea } from '@/components/ui/textarea'
import { useAuth } from '@/hooks/useAuth'
import {
  useAccessCatalog,
  useCreateAccessRequest,
  useAccessRequests,
} from '@/hooks/usePermissions'

const STATUS_VARIANT = {
  requested: 'warning',
  active: 'success',
  rejected: 'error',
  invalid: 'error',
  revoked: 'secondary',
  expired: 'secondary',
}

function formatDate(iso) {
  if (!iso) return '-'
  return new Date(iso).toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: '2-digit',
    hour: '2-digit', minute: '2-digit',
  })
}

function RequestRow({ req, isAdmin }) {
  return (
    <TableRow>
      {isAdmin && (
        <TableCell className="text-xs font-mono text-muted-foreground">
          {req.user_id}
        </TableCell>
      )}
      <TableCell className="font-mono text-sm">{req.permission_key}</TableCell>
      <TableCell className="text-sm">{req.duration_hours}h</TableCell>
      <TableCell>
        <Badge variant={STATUS_VARIANT[req.status] ?? 'outline'}>
          {req.status}
        </Badge>
      </TableCell>
      <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
        {req.status === 'active' ? formatDate(req.expires_at) : '-'}
      </TableCell>
      <TableCell className="text-xs text-muted-foreground">
        {formatDate(req.created_at)}
      </TableCell>
      <TableCell>
        {req.shortcut_story_url ? (
          <a
            href={req.shortcut_story_url}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-xs text-primary underline-offset-4 hover:underline"
          >
            Card
            <ExternalLink className="h-3 w-3" />
          </a>
        ) : (
          <span className="text-xs text-muted-foreground">-</span>
        )}
      </TableCell>
    </TableRow>
  )
}

export default function ElevatedAccessPage() {
  const { role } = useAuth()
  const isAdmin = role === 'admin'

  const catalog = useAccessCatalog()
  const requests = useAccessRequests()
  const createMutation = useCreateAccessRequest()

  const [selectedKey, setSelectedKey] = useState('')

  const selectedEntry = catalog.data?.entries?.find((e) => e.permission_key === selectedKey)

  const schema = z.object({
    duration_hours: z
      .string()
      .transform(Number)
      .pipe(
        z
          .number()
          .int('Must be a whole number')
          .min(1, 'At least 1 hour')
          .max(selectedEntry?.max_duration_hours ?? 72, `Max ${selectedEntry?.max_duration_hours ?? 72} hours`),
      ),
    justification: z.string().min(10, 'Provide at least 10 characters'),
  })

  const { register, handleSubmit, reset, formState: { errors } } = useForm({
    resolver: zodResolver(schema),
    defaultValues: { duration_hours: '1', justification: '' },
  })

  async function onSubmit(values) {
    await createMutation.mutateAsync({
      permission_key: selectedKey,
      duration_hours: values.duration_hours,
      justification: values.justification,
    })
    reset()
    setSelectedKey('')
  }

  const catalogEnabled = catalog.data?.enabled ?? false
  const entries = catalog.data?.entries ?? []

  return (
    <div className="space-y-8">
      {/* Page header */}
      <div>
        <h1 className="text-2xl font-bold">Elevated Access</h1>
        <p className="text-sm text-muted-foreground">
          Request temporary elevated access that requires lead approval via Shortcut.
        </p>
      </div>

      {/* Request form */}
      <Card className="bg-surface border-surface-border">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5" />
            New Access Request
          </CardTitle>
        </CardHeader>
        <CardContent>
          {catalog.isLoading && (
            <div className="space-y-3">
              <Skeleton className="h-10 w-full max-w-sm" />
              <Skeleton className="h-10 w-48" />
              <Skeleton className="h-24 w-full" />
            </div>
          )}
          {catalog.isError && (
            <p className="text-sm text-destructive">
              Failed to load access catalog: {catalog.error?.message}
            </p>
          )}
          {!catalog.isLoading && !catalog.isError && !catalogEnabled && (
            <p className="text-sm text-muted-foreground">
              Elevated access requests are not configured for this environment.
            </p>
          )}
          {!catalog.isLoading && !catalog.isError && catalogEnabled && (
            <form onSubmit={handleSubmit(onSubmit)} className="space-y-5 max-w-lg">
              {/* Permission select */}
              <div className="space-y-1.5">
                <Label>Permission</Label>
                <Select value={selectedKey} onValueChange={setSelectedKey}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select access type…" />
                  </SelectTrigger>
                  <SelectContent>
                    {entries.map((e) => (
                      <SelectItem key={e.permission_key} value={e.permission_key}>
                        {e.permission_key}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {selectedEntry && (
                  <p className="text-xs text-muted-foreground">
                    {selectedEntry.description} · Max {selectedEntry.max_duration_hours}h
                  </p>
                )}
              </div>

              {/* Duration */}
              <div className="space-y-1.5">
                <Label htmlFor="duration">Duration (hours)</Label>
                <Input
                  id="duration"
                  type="number"
                  min={1}
                  max={selectedEntry?.max_duration_hours ?? 72}
                  className="w-32"
                  {...register('duration_hours')}
                />
                {errors.duration_hours && (
                  <p className="text-xs text-destructive">{errors.duration_hours.message}</p>
                )}
              </div>

              {/* Justification */}
              <div className="space-y-1.5">
                <Label htmlFor="justification">Justification</Label>
                <Textarea
                  id="justification"
                  placeholder="Describe why you need this access…"
                  rows={3}
                  {...register('justification')}
                />
                {errors.justification && (
                  <p className="text-xs text-destructive">{errors.justification.message}</p>
                )}
              </div>

              {createMutation.isError && (
                <p className="text-sm text-destructive">
                  {createMutation.error?.response?.data?.detail ?? createMutation.error?.message}
                </p>
              )}

              <Button
                type="submit"
                disabled={!selectedKey || createMutation.isPending}
              >
                {createMutation.isPending ? 'Submitting…' : 'Submit Request'}
              </Button>
            </form>
          )}
        </CardContent>
      </Card>

      {/* Requests table */}
      <Card className="bg-surface border-surface-border">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Clock className="h-5 w-5" />
            {isAdmin ? 'All Requests' : 'My Requests'}
          </CardTitle>
        </CardHeader>
        <CardContent>
          {requests.isLoading && (
            <div className="space-y-2">
              {[...Array(3)].map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}
            </div>
          )}
          {requests.isError && (
            <p className="text-sm text-destructive">
              Failed to load requests: {requests.error?.message}
            </p>
          )}
          {!requests.isLoading && !requests.isError && (requests.data?.length ?? 0) === 0 && (
            <p className="text-sm text-muted-foreground py-4">No access requests yet.</p>
          )}
          {!requests.isLoading && !requests.isError && (requests.data?.length ?? 0) > 0 && (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    {isAdmin && <TableHead className="w-[80px]">User ID</TableHead>}
                    <TableHead>Permission</TableHead>
                    <TableHead className="w-[80px]">Duration</TableHead>
                    <TableHead className="w-[110px]">Status</TableHead>
                    <TableHead className="w-[160px]">Expires</TableHead>
                    <TableHead className="w-[160px]">Requested</TableHead>
                    <TableHead className="w-[80px]">Card</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {requests.data.map((req) => (
                    <RequestRow key={req.id} req={req} isAdmin={isAdmin} />
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
