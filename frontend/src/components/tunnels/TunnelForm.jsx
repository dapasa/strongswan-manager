import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useForm, useFieldArray } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { Plus, Trash2, ChevronDown, ChevronUp } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { useCreateTunnel, useUpdateTunnel } from '@/hooks/useTunnels'

const DPD_ACTIONS = ['none', 'clear', 'restart']

const ipv4Regex = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/
const cidrRegex = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\/(?:3[0-2]|[12]?\d)$/

/**
 * Validates that a CIDR string is a valid IPv4 network with no host bits set.
 * Python's IPv4Network(strict=True) rejects CIDRs like 10.0.0.1/24 because
 * the host bits are non-zero. This mirrors that behaviour on the client so
 * errors are caught before the request is ever sent.
 */
function isStrictIpv4Network(cidr) {
  if (!cidrRegex.test(cidr)) return false
  const [ip, prefixStr] = cidr.split('/')
  const prefix = parseInt(prefixStr, 10)
  const octets = ip.split('.').map(Number)
  const ipInt =
    (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
  // For prefix /p, the host mask is (2^(32-p) - 1). Host bits must all be 0.
  const hostBits = 32 - prefix
  const hostMask = hostBits === 32 ? 0xffffffff : (1 << hostBits) - 1
  return (ipInt & hostMask) === 0
}

const cidrEntry = z.object({
  value: z
    .string()
    .regex(cidrRegex, 'Must be a valid CIDR (e.g. 10.0.0.0/24)')
    .refine(isStrictIpv4Network, 'Host bits must be zero (e.g. use 10.0.0.0/24, not 10.0.0.1/24)'),
})

// Peer IP must be a plain IPv4 address — no CIDR prefix, no leading zeros trick.
// 0.0.0.0 and loopback (127.x.x.x) are accepted by the backend (IPv4Address type)
// so we intentionally do NOT block them here.
function isNotCidr(value) {
  return !value.includes('/')
}

function buildSchema(mode) {
  const baseSchema = z.object({
    name: z.string().min(1, 'Name is required').max(255, 'Name must be 255 characters or less'),
    description: z.string().optional().default(''),
    peer_ip: z
      .string()
      .min(1, 'Peer IP is required')
      .refine(isNotCidr, 'Enter an IP address, not a CIDR (remove the /prefix)')
      .regex(ipv4Regex, 'Must be a valid IPv4 address'),
    local_cidrs: z
      .array(cidrEntry)
      .min(1, 'At least one local CIDR is required')
      .max(64, 'Cannot exceed 64 local CIDRs'),
    remote_cidrs: z
      .array(cidrEntry)
      .min(1, 'At least one remote CIDR is required')
      .max(64, 'Cannot exceed 64 remote CIDRs'),
    ike_version: z.enum(['1', '2']),
    // Create: required, min 1 char (matches backend min_length=1).
    // Edit: optional — empty string means "keep existing key". If the user
    // types something it must be at least 1 char (backend TunnelUpdate.psk
    // has min_length=1). We apply a 2048-char cap as a sanity guard.
    psk:
      mode === 'create'
        ? z
            .string()
            .min(1, 'Pre-shared key is required')
            .max(2048, 'Pre-shared key must be 2048 characters or less')
        : z
            .string()
            .max(2048, 'Pre-shared key must be 2048 characters or less')
            .refine(
              (v) => v === '' || v.length >= 1,
              'If changing the key, it must not be empty',
            )
            .optional()
            .default(''),
    ike_proposals: z.string().optional().default(''),
    esp_proposals: z.string().optional().default(''),
    dpd_action: z.enum(['none', 'clear', 'restart']).optional().default('restart'),
    dpd_delay: z
      .string()
      .transform((v) => (v === '' ? null : Number(v)))
      .pipe(z.number().int().min(1, 'Must be at least 1 second').max(3600, 'Must be 3600 seconds or less').nullable())
      .optional(),
    dpd_timeout: z
      .string()
      .transform((v) => (v === '' ? null : Number(v)))
      .pipe(z.number().int().min(1, 'Must be at least 1 second').max(86400, 'Must be 86400 seconds or less').nullable())
      .optional(),
  })

  // Cross-field: dpd_timeout must be strictly greater than dpd_delay when
  // both are non-null integers. StrongSwan will misbehave if the timeout fires
  // at the same moment as (or before) the keepalive delay.
  return baseSchema.superRefine((data, ctx) => {
    const delay = data.dpd_delay
    const timeout = data.dpd_timeout
    if (delay != null && timeout != null && timeout <= delay) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `DPD Timeout (${timeout}s) must be greater than DPD Delay (${delay}s)`,
        path: ['dpd_timeout'],
      })
    }
  })
}

/**
 * Tunnel create/edit form using React Hook Form + Zod.
 *
 * @param {{ mode: 'create'|'edit', tunnel?: object }} props
 */
export default function TunnelForm({ mode = 'create', tunnel }) {
  const [advancedOpen, setAdvancedOpen] = useState(false)
  const navigate = useNavigate()
  const createMutation = useCreateTunnel()
  const updateMutation = useUpdateTunnel()
  const isEdit = mode === 'edit'
  const mutation = isEdit ? updateMutation : createMutation

  const schema = buildSchema(mode)

  const {
    register,
    handleSubmit,
    control,
    setValue,
    watch,
    formState: { errors, isSubmitting },
  } = useForm({
    resolver: zodResolver(schema),
    defaultValues: {
      name: tunnel?.name ?? '',
      description: tunnel?.description ?? '',
      peer_ip: tunnel?.peer_ip ?? '',
      local_cidrs: tunnel?.local_cidrs?.map((c) => ({ value: c })) ?? [{ value: '' }],
      remote_cidrs: tunnel?.remote_cidrs?.map((c) => ({ value: c })) ?? [{ value: '' }],
      ike_version: tunnel?.ike_version ?? '2',
      psk: '',
      ike_proposals: tunnel?.ike_proposals ?? '',
      esp_proposals: tunnel?.esp_proposals ?? '',
      dpd_action: tunnel?.dpd_action ?? 'restart',
      dpd_delay: tunnel?.dpd_delay != null ? String(tunnel.dpd_delay) : '30',
      dpd_timeout: tunnel?.dpd_timeout != null ? String(tunnel.dpd_timeout) : '150',
    },
  })

  const localCidrs = useFieldArray({ control, name: 'local_cidrs' })
  const remoteCidrs = useFieldArray({ control, name: 'remote_cidrs' })

  const ikeVersion = watch('ike_version')

  async function onSubmit(values) {
    const payload = {
      name: values.name,
      description: values.description || null,
      peer_ip: values.peer_ip,
      local_cidrs: values.local_cidrs.map((c) => c.value),
      remote_cidrs: values.remote_cidrs.map((c) => c.value),
      ike_version: values.ike_version,
      ike_proposals: values.ike_proposals || null,
      esp_proposals: values.esp_proposals || null,
      dpd_action: values.dpd_action,
      dpd_delay: values.dpd_delay ?? 30,
      dpd_timeout: values.dpd_timeout ?? 150,
    }

    // Only include psk if provided (required on create, optional on edit)
    if (values.psk) {
      payload.psk = values.psk
    }

    try {
      if (isEdit) {
        await mutation.mutateAsync({ id: tunnel.id, data: payload })
        navigate(`/tunnels/${tunnel.id}`)
      } else {
        const created = await mutation.mutateAsync(payload)
        navigate(`/tunnels/${created.id}`)
      }
    } catch {
      // mutation.onError already shows a toast; stay on the form so the
      // user can correct their input without losing what they typed.
    }
  }

  return (
    <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
      <Card className="bg-surface border-surface-border">
        <CardHeader>
          <CardTitle>General</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="name">Name *</Label>
            <Input id="name" placeholder="my-vpn-tunnel" {...register('name')} />
            {errors.name && (
              <p className="text-sm text-destructive">{errors.name.message}</p>
            )}
          </div>

          <div className="space-y-2">
            <Label htmlFor="description">Description</Label>
            <Textarea
              id="description"
              placeholder="Optional description..."
              {...register('description')}
            />
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="peer_ip">Peer IP *</Label>
              <Input id="peer_ip" placeholder="203.0.113.1" {...register('peer_ip')} />
              {errors.peer_ip && (
                <p className="text-sm text-destructive">{errors.peer_ip.message}</p>
              )}
            </div>

            <div className="space-y-2">
              <Label htmlFor="ike_version">IKE Version</Label>
              <Select
                value={ikeVersion}
                onValueChange={(val) => setValue('ike_version', val)}
              >
                <SelectTrigger id="ike_version">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="1">IKEv1</SelectItem>
                  <SelectItem value="2">IKEv2</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="space-y-2">
            <Label htmlFor="psk">
              Pre-Shared Key {isEdit ? '(leave blank to keep current)' : '*'}
            </Label>
            <Input
              id="psk"
              type="password"
              placeholder={isEdit ? '********' : 'Enter pre-shared key'}
              {...register('psk')}
            />
            {errors.psk && (
              <p className="text-sm text-destructive">{errors.psk.message}</p>
            )}
          </div>
        </CardContent>
      </Card>

      <Card className="bg-surface border-surface-border">
        <CardHeader>
          <CardTitle>Network</CardTitle>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Local CIDRs */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <Label>Local CIDRs *</Label>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => localCidrs.append({ value: '' })}
              >
                <Plus className="h-3.5 w-3.5" />
                Add
              </Button>
            </div>
            {localCidrs.fields.map((field, index) => (
              <div key={field.id} className="flex items-start gap-2">
                <div className="flex-1">
                  <Input
                    placeholder="10.0.0.0/24"
                    {...register(`local_cidrs.${index}.value`)}
                  />
                  {errors.local_cidrs?.[index]?.value && (
                    <p className="mt-1 text-sm text-destructive">
                      {errors.local_cidrs[index].value.message}
                    </p>
                  )}
                </div>
                {localCidrs.fields.length > 1 && (
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    onClick={() => localCidrs.remove(index)}
                    className="text-muted-foreground hover:text-destructive"
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                )}
              </div>
            ))}
            {errors.local_cidrs?.root && (
              <p className="text-sm text-destructive">{errors.local_cidrs.root.message}</p>
            )}
            {errors.local_cidrs?.message && (
              <p className="text-sm text-destructive">{errors.local_cidrs.message}</p>
            )}
          </div>

          {/* Remote CIDRs */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <Label>Remote CIDRs *</Label>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => remoteCidrs.append({ value: '' })}
              >
                <Plus className="h-3.5 w-3.5" />
                Add
              </Button>
            </div>
            {remoteCidrs.fields.map((field, index) => (
              <div key={field.id} className="flex items-start gap-2">
                <div className="flex-1">
                  <Input
                    placeholder="192.168.1.0/24"
                    {...register(`remote_cidrs.${index}.value`)}
                  />
                  {errors.remote_cidrs?.[index]?.value && (
                    <p className="mt-1 text-sm text-destructive">
                      {errors.remote_cidrs[index].value.message}
                    </p>
                  )}
                </div>
                {remoteCidrs.fields.length > 1 && (
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    onClick={() => remoteCidrs.remove(index)}
                    className="text-muted-foreground hover:text-destructive"
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                )}
              </div>
            ))}
            {errors.remote_cidrs?.root && (
              <p className="text-sm text-destructive">{errors.remote_cidrs.root.message}</p>
            )}
            {errors.remote_cidrs?.message && (
              <p className="text-sm text-destructive">{errors.remote_cidrs.message}</p>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Advanced Settings (collapsible) */}
      <Card className="bg-surface border-surface-border">
        <CardHeader
          className="cursor-pointer select-none"
          onClick={() => setAdvancedOpen((v) => !v)}
        >
          <div className="flex items-center justify-between">
            <CardTitle>Advanced Settings</CardTitle>
            {advancedOpen ? (
              <ChevronUp className="h-4 w-4 text-muted-foreground" />
            ) : (
              <ChevronDown className="h-4 w-4 text-muted-foreground" />
            )}
          </div>
        </CardHeader>
        {advancedOpen && (
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="ike_proposals">IKE Proposals</Label>
                <Input
                  id="ike_proposals"
                  placeholder="e.g. aes256-sha256-modp2048"
                  {...register('ike_proposals')}
                />
                {errors.ike_proposals && (
                  <p className="text-sm text-destructive">{errors.ike_proposals.message}</p>
                )}
              </div>

              <div className="space-y-2">
                <Label htmlFor="esp_proposals">ESP Proposals</Label>
                <Input
                  id="esp_proposals"
                  placeholder="e.g. aes256-sha256"
                  {...register('esp_proposals')}
                />
                {errors.esp_proposals && (
                  <p className="text-sm text-destructive">{errors.esp_proposals.message}</p>
                )}
              </div>
            </div>

            <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
              <div className="space-y-2">
                <Label htmlFor="dpd_action">DPD Action</Label>
                <Select
                  value={watch('dpd_action')}
                  onValueChange={(val) => setValue('dpd_action', val)}
                >
                  <SelectTrigger id="dpd_action">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {DPD_ACTIONS.map((a) => (
                      <SelectItem key={a} value={a}>
                        {a}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label htmlFor="dpd_delay">DPD Delay (seconds)</Label>
                <Input
                  id="dpd_delay"
                  type="number"
                  min={1}
                  placeholder="30"
                  {...register('dpd_delay')}
                />
                {errors.dpd_delay && (
                  <p className="text-sm text-destructive">{errors.dpd_delay.message}</p>
                )}
              </div>

              <div className="space-y-2">
                <Label htmlFor="dpd_timeout">DPD Timeout (seconds)</Label>
                <Input
                  id="dpd_timeout"
                  type="number"
                  min={1}
                  placeholder="150"
                  {...register('dpd_timeout')}
                />
                {errors.dpd_timeout && (
                  <p className="text-sm text-destructive">{errors.dpd_timeout.message}</p>
                )}
              </div>
            </div>
          </CardContent>
        )}
      </Card>

      <div className="flex items-center justify-end gap-3">
        <Button type="button" variant="outline" onClick={() => navigate(-1)}>
          Cancel
        </Button>
        <Button type="submit" disabled={isSubmitting || mutation.isPending}>
          {mutation.isPending
            ? isEdit ? 'Saving...' : 'Creating...'
            : isEdit ? 'Save Changes' : 'Create Tunnel'}
        </Button>
      </div>

      {mutation.isError && (
        <div className="rounded-lg border border-destructive/50 bg-destructive/10 p-4">
          <p className="text-sm text-destructive">
            {mutation.error?.response?.data?.detail ?? mutation.error?.message ?? 'An error occurred'}
          </p>
        </div>
      )}
    </form>
  )
}
