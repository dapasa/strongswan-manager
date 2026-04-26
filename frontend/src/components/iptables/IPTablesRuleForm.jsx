import { useState } from 'react'
import { useForm, Controller } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { Plus, ChevronUp } from 'lucide-react'
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
import { useCreateIptablesRule, useUpdateIptablesRule } from '@/hooks/useIptablesRules'
import CommandPreview, { buildCommandString } from './CommandPreview'

const cidrRegex = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\/(?:3[0-2]|[12]?\d)$/

const CHAINS = ['INPUT', 'FORWARD', 'OUTPUT']
const PROTOCOLS = ['tcp', 'udp', 'icmp', 'all']
const ACTIONS = ['ACCEPT', 'DROP', 'REJECT']
const STATE_OPTIONS = ['NEW', 'ESTABLISHED', 'RELATED', 'INVALID']

const iptablesRuleSchema = z.object({
  chain: z.enum(['INPUT', 'FORWARD', 'OUTPUT']),
  protocol: z.enum(['tcp', 'udp', 'icmp', 'all']),
  source_cidr: z
    .string()
    .regex(cidrRegex, 'Must be a valid CIDR (e.g. 10.0.0.0/24)')
    .or(z.literal(''))
    .transform((v) => v || null),
  dest_cidr: z
    .string()
    .regex(cidrRegex, 'Must be a valid CIDR (e.g. 10.0.0.0/24)')
    .or(z.literal(''))
    .transform((v) => v || null),
  sport: z
    .string()
    .transform((v) => (v === '' ? null : Number(v)))
    .pipe(z.number().int().min(1).max(65535).nullable()),
  dport: z
    .string()
    .transform((v) => (v === '' ? null : Number(v)))
    .pipe(z.number().int().min(1).max(65535).nullable()),
  action: z.enum(['ACCEPT', 'DROP', 'REJECT']),
  state_match: z.array(z.enum(['NEW', 'ESTABLISHED', 'RELATED', 'INVALID'])).optional().default([]),
  comment: z
    .string()
    .max(256, 'Comment must be 256 characters or fewer')
    .refine(
      (val) => !val || !/[;|&$`(){}\\]/.test(val),
      'Comment must not contain special characters (;|&$`(){}\\)'
    )
    .optional()
    .default(''),
  position: z
    .string()
    .transform((v) => (v === '' ? null : Number(v)))
    .pipe(z.number().int().min(0).nullable()),
}).refine(
  (data) => {
    if ((data.sport != null || data.dport != null) && !['tcp', 'udp'].includes(data.protocol)) {
      return false
    }
    return true
  },
  { message: 'Ports require protocol tcp or udp', path: ['protocol'] }
)

/**
 * Inline form for creating or editing an iptables rule.
 *
 * @param {{
 *   tunnelId: number|string,
 *   editRule?: object|null,
 *   onClose?: () => void,
 * }} props
 */
export default function IPTablesRuleForm({ tunnelId, editRule = null, onClose }) {
  const [expanded, setExpanded] = useState(!!editRule)
  const createMutation = useCreateIptablesRule(tunnelId)
  const updateMutation = useUpdateIptablesRule(tunnelId)
  const isEdit = !!editRule

  const defaultValues = editRule
    ? {
        chain: editRule.chain,
        protocol: editRule.protocol,
        source_cidr: editRule.source_cidr ?? '',
        dest_cidr: editRule.dest_cidr ?? '',
        sport: editRule.sport != null ? String(editRule.sport) : '',
        dport: editRule.dport != null ? String(editRule.dport) : '',
        action: editRule.action,
        state_match: editRule.state_match ?? [],
        comment: editRule.comment ?? '',
        position: editRule.position != null ? String(editRule.position) : '',
      }
    : {
        chain: 'FORWARD',
        protocol: 'tcp',
        source_cidr: '',
        dest_cidr: '',
        sport: '',
        dport: '',
        action: 'ACCEPT',
        state_match: [],
        comment: '',
        position: '',
      }

  const {
    register,
    handleSubmit,
    control,
    watch,
    reset,
    formState: { errors },
  } = useForm({
    resolver: zodResolver(iptablesRuleSchema),
    defaultValues,
  })

  const watchedValues = watch()
  const commandPreview = buildCommandString({
    chain: watchedValues.chain,
    protocol: watchedValues.protocol,
    source_cidr: watchedValues.source_cidr,
    dest_cidr: watchedValues.dest_cidr,
    sport: watchedValues.sport ? Number(watchedValues.sport) : null,
    dport: watchedValues.dport ? Number(watchedValues.dport) : null,
    action: watchedValues.action,
    state_match: watchedValues.state_match,
    comment: watchedValues.comment,
    position: watchedValues.position ? Number(watchedValues.position) : null,
  })

  const protocol = watchedValues.protocol
  const portsDisabled = protocol !== 'tcp' && protocol !== 'udp'
  const mutation = isEdit ? updateMutation : createMutation

  async function onSubmit(values) {
    const payload = {
      chain: values.chain,
      protocol: values.protocol,
      source_cidr: values.source_cidr || null,
      dest_cidr: values.dest_cidr || null,
      sport: values.sport,
      dport: values.dport,
      action: values.action,
      state_match: values.state_match?.length > 0 ? values.state_match : null,
      comment: values.comment || null,
      position: values.position,
    }

    if (isEdit) {
      await updateMutation.mutateAsync({ ruleId: editRule.id, ruleData: payload })
    } else {
      await createMutation.mutateAsync(payload)
    }

    reset()
    handleClose()
  }

  function handleClose() {
    if (!isEdit) setExpanded(false)
    onClose?.()
  }

  if (!expanded && !isEdit) {
    return (
      <Button
        variant="outline"
        size="sm"
        onClick={() => setExpanded(true)}
        className="gap-1.5"
      >
        <Plus className="h-3.5 w-3.5" />
        Add Rule
      </Button>
    )
  }

  return (
    <div className="space-y-3 rounded-lg border border-surface-border bg-surface p-4">
      <div className="flex items-center justify-between">
        <h4 className="text-sm font-medium">{isEdit ? 'Edit Rule' : 'New IPTables Rule'}</h4>
        <Button variant="ghost" size="sm" onClick={handleClose}>
          <ChevronUp className="h-4 w-4" />
        </Button>
      </div>

      {/* Live command preview */}
      <CommandPreview command={commandPreview} />

      <form onSubmit={handleSubmit(onSubmit)} className="space-y-3">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {/* Chain */}
          <div className="space-y-1.5">
            <Label>Chain *</Label>
            <Controller
              name="chain"
              control={control}
              render={({ field }) => (
                <Select value={field.value} onValueChange={field.onChange}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select chain" />
                  </SelectTrigger>
                  <SelectContent>
                    {CHAINS.map((c) => (
                      <SelectItem key={c} value={c}>{c}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
            />
            {errors.chain && <p className="text-xs text-destructive">{errors.chain.message}</p>}
          </div>

          {/* Protocol */}
          <div className="space-y-1.5">
            <Label>Protocol *</Label>
            <Controller
              name="protocol"
              control={control}
              render={({ field }) => (
                <Select value={field.value} onValueChange={field.onChange}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select protocol" />
                  </SelectTrigger>
                  <SelectContent>
                    {PROTOCOLS.map((p) => (
                      <SelectItem key={p} value={p}>{p}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
            />
            {errors.protocol && <p className="text-xs text-destructive">{errors.protocol.message}</p>}
          </div>

          {/* Action */}
          <div className="space-y-1.5">
            <Label>Action *</Label>
            <Controller
              name="action"
              control={control}
              render={({ field }) => (
                <Select value={field.value} onValueChange={field.onChange}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select action" />
                  </SelectTrigger>
                  <SelectContent>
                    {ACTIONS.map((a) => (
                      <SelectItem key={a} value={a}>{a}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
            />
            {errors.action && <p className="text-xs text-destructive">{errors.action.message}</p>}
          </div>

          {/* Source CIDR */}
          <div className="space-y-1.5">
            <Label htmlFor="rule-source">Source CIDR</Label>
            <Input
              id="rule-source"
              placeholder="10.0.0.0/24"
              {...register('source_cidr')}
            />
            {errors.source_cidr && <p className="text-xs text-destructive">{errors.source_cidr.message}</p>}
          </div>

          {/* Destination CIDR */}
          <div className="space-y-1.5">
            <Label htmlFor="rule-dest">Destination CIDR</Label>
            <Input
              id="rule-dest"
              placeholder="192.168.1.0/24"
              {...register('dest_cidr')}
            />
            {errors.dest_cidr && <p className="text-xs text-destructive">{errors.dest_cidr.message}</p>}
          </div>

          {/* Source Port */}
          <div className="space-y-1.5">
            <Label htmlFor="rule-sport">Source Port</Label>
            <Input
              id="rule-sport"
              type="number"
              min={1}
              max={65535}
              placeholder="Optional"
              disabled={portsDisabled}
              {...register('sport')}
            />
            {errors.sport && <p className="text-xs text-destructive">{errors.sport.message}</p>}
          </div>

          {/* Destination Port */}
          <div className="space-y-1.5">
            <Label htmlFor="rule-dport">Destination Port</Label>
            <Input
              id="rule-dport"
              type="number"
              min={1}
              max={65535}
              placeholder="Optional"
              disabled={portsDisabled}
              {...register('dport')}
            />
            {errors.dport && <p className="text-xs text-destructive">{errors.dport.message}</p>}
          </div>

          {/* Position */}
          <div className="space-y-1.5">
            <Label htmlFor="rule-position">Position</Label>
            <Input
              id="rule-position"
              type="number"
              min={0}
              placeholder="Append (default)"
              {...register('position')}
            />
            {errors.position && <p className="text-xs text-destructive">{errors.position.message}</p>}
          </div>

          {/* State Match */}
          <div className="space-y-1.5">
            <Label>State Match</Label>
            <Controller
              name="state_match"
              control={control}
              render={({ field }) => (
                <div className="flex flex-wrap gap-2">
                  {STATE_OPTIONS.map((state) => {
                    const isChecked = field.value?.includes(state)
                    return (
                      <label key={state} className="flex items-center gap-1 text-xs">
                        <input
                          type="checkbox"
                          checked={isChecked}
                          onChange={(e) => {
                            if (e.target.checked) {
                              field.onChange([...(field.value ?? []), state])
                            } else {
                              field.onChange((field.value ?? []).filter((s) => s !== state))
                            }
                          }}
                          className="h-3.5 w-3.5 rounded border-input"
                        />
                        {state}
                      </label>
                    )
                  })}
                </div>
              )}
            />
          </div>
        </div>

        {/* Comment */}
        <div className="space-y-1.5">
          <Label htmlFor="rule-comment">Comment</Label>
          <Input
            id="rule-comment"
            placeholder="Optional description"
            maxLength={256}
            {...register('comment')}
          />
          {errors.comment && <p className="text-xs text-destructive">{errors.comment.message}</p>}
        </div>

        <div className="flex items-center gap-2">
          <Button
            type="submit"
            size="sm"
            disabled={mutation.isPending}
          >
            {mutation.isPending
              ? (isEdit ? 'Updating...' : 'Creating...')
              : (isEdit ? 'Update Rule' : 'Create Rule')
            }
          </Button>
          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={() => {
              reset()
              handleClose()
            }}
          >
            Cancel
          </Button>
        </div>

        {mutation.isError && (
          <p className="text-xs text-destructive">
            {mutation.error?.response?.data?.detail ?? mutation.error?.message ?? `Failed to ${isEdit ? 'update' : 'create'} rule`}
          </p>
        )}
      </form>
    </div>
  )
}
