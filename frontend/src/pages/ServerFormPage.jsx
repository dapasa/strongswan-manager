import { useState } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import { useForm, Controller } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { ArrowLeft, Plug, AlertTriangle } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Skeleton } from '@/components/ui/skeleton'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useServer, useCreateServer, useUpdateServer, useTestConnection } from '@/hooks/useServers'

const EC2_INSTANCE_ID_RE = /^i-[0-9a-f]{17}$/

function buildSchema(mode, editingKey) {
  return z
    .object({
      connection_type: z.enum(['ssh', 'ssm']),
      name: z.string().min(1, 'Name is required').max(255, 'Name must be 255 characters or less'),
      description: z.string().optional().default(''),
      // SSH fields
      hostname: z.string().optional().default(''),
      ssh_port: z.string().optional().default('22'),
      ssh_user: z.string().optional().default(''),
      ssh_private_key: z.string().optional().default(''),
      // SSM fields
      ec2_instance_id: z.string().optional().default(''),
      aws_role_arn: z.string().optional().default(''),
      aws_region_override: z.string().optional().default(''),
    })
    .superRefine((data, ctx) => {
      if (data.connection_type === 'ssh') {
        if (!data.hostname) {
          ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'Hostname is required', path: ['hostname'] })
        }
        const port = Number(data.ssh_port)
        if (!data.ssh_port || isNaN(port) || port < 1 || port > 65535) {
          ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'Port must be between 1 and 65535', path: ['ssh_port'] })
        }
        if (!data.ssh_user) {
          ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'SSH user is required', path: ['ssh_user'] })
        }
        if (mode === 'create' || editingKey) {
          if (!data.ssh_private_key) {
            ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'SSH private key is required', path: ['ssh_private_key'] })
          }
        }
      }

      if (data.connection_type === 'ssm') {
        if (!data.ec2_instance_id) {
          ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'EC2 Instance ID is required', path: ['ec2_instance_id'] })
        } else if (!EC2_INSTANCE_ID_RE.test(data.ec2_instance_id)) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: 'Must be in format i-<17 hex chars> (e.g. i-0e8545d009894bb9d)',
            path: ['ec2_instance_id'],
          })
        }
      }
    })
}

/**
 * Server create/edit form page.
 *
 * @param {{ mode: 'create' | 'edit' }} props
 */
export default function ServerFormPage({ mode = 'create' }) {
  const { id } = useParams()
  const navigate = useNavigate()
  const isEdit = mode === 'edit'
  const [editingKey, setEditingKey] = useState(false)

  const server = useServer(id, { enabled: isEdit })
  const createMutation = useCreateServer()
  const updateMutation = useUpdateServer()
  const testConnection = useTestConnection()
  const mutation = isEdit ? updateMutation : createMutation

  const schema = buildSchema(mode, editingKey)

  const originalType = server.data?.connection_type ?? 'ssh'

  const {
    register,
    handleSubmit,
    control,
    watch,
    formState: { errors, isSubmitting },
  } = useForm({
    resolver: zodResolver(schema),
    defaultValues: {
      connection_type: 'ssh',
      name: '',
      description: '',
      hostname: '',
      ssh_port: '22',
      ssh_user: 'admin',
      ssh_private_key: '',
      ec2_instance_id: '',
      aws_role_arn: '',
      aws_region_override: '',
    },
    values: isEdit && server.data ? {
      connection_type: server.data.connection_type ?? 'ssh',
      name: server.data.name ?? '',
      description: server.data.description ?? '',
      hostname: server.data.hostname ?? '',
      ssh_port: String(server.data.ssh_port ?? 22),
      ssh_user: server.data.ssh_user ?? 'admin',
      ssh_private_key: '',
      ec2_instance_id: server.data.ec2_instance_id ?? '',
      aws_role_arn: server.data.aws_role_arn ?? '',
      aws_region_override: server.data.aws_region_override ?? '',
    } : undefined,
  })

  const connectionType = watch('connection_type')
  const typeChanged = isEdit && server.data && connectionType !== originalType

  const [testingConnection, setTestingConnection] = useState(false)

  async function handleTestConnection() {
    setTestingConnection(true)
    try {
      await testConnection.mutateAsync(Number(id))
    } finally {
      setTestingConnection(false)
    }
  }

  async function onSubmit(values) {
    let payload = {
      connection_type: values.connection_type,
      name: values.name,
      description: values.description || null,
    }

    if (values.connection_type === 'ssh') {
      payload.hostname = values.hostname
      payload.ssh_port = Number(values.ssh_port) || 22
      payload.ssh_user = values.ssh_user
      if (values.ssh_private_key) {
        payload.ssh_private_key = values.ssh_private_key
      }
      // Clear SSM fields
      payload.ec2_instance_id = null
      payload.aws_role_arn = null
      payload.aws_region_override = null
    } else {
      payload.ec2_instance_id = values.ec2_instance_id
      payload.aws_role_arn = values.aws_role_arn || null
      payload.aws_region_override = values.aws_region_override || null
      // Clear SSH fields
      payload.hostname = null
      payload.ssh_port = null
      payload.ssh_user = null
    }

    if (isEdit) {
      await mutation.mutateAsync({ id: Number(id), data: payload })
      navigate('/servers')
    } else {
      await mutation.mutateAsync(payload)
      navigate('/servers')
    }
  }

  if (isEdit && server.isLoading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-4 w-96" />
        <Skeleton className="h-64 w-full" />
      </div>
    )
  }

  if (isEdit && server.isError) {
    return (
      <div className="space-y-4">
        <Button variant="ghost" onClick={() => navigate('/servers')}>
          <ArrowLeft className="h-4 w-4" />
          Back to Servers
        </Button>
        <div className="rounded-lg border border-destructive/50 bg-destructive/10 p-4">
          <p className="text-sm text-destructive">
            Failed to load server: {server.error?.response?.data?.detail ?? server.error?.message ?? 'Unknown error'}
          </p>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Button variant="ghost" size="icon" asChild>
          <Link to="/servers">
            <ArrowLeft className="h-4 w-4" />
          </Link>
        </Button>
        <div>
          <h1 className="text-2xl font-bold">
            {isEdit ? 'Edit Server' : 'Add Server'}
          </h1>
          <p className="text-sm text-muted-foreground">
            {isEdit
              ? `Editing ${server.data?.name ?? 'server'}`
              : 'Configure a new server connection.'}
          </p>
        </div>
      </div>

      <div className="max-w-2xl">
        <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
          <Card className="bg-surface border-surface-border">
            <CardHeader>
              <CardTitle>Connection Details</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Server name */}
              <div className="space-y-2">
                <Label htmlFor="name">Name *</Label>
                <Input id="name" placeholder="production-vpn-1" {...register('name')} />
                {errors.name && (
                  <p className="text-sm text-destructive">{errors.name.message}</p>
                )}
              </div>

              {/* Connection type selector */}
              <div className="space-y-2">
                <Label htmlFor="connection_type">Connection Type *</Label>
                <Controller
                  name="connection_type"
                  control={control}
                  render={({ field }) => (
                    <Select
                      value={field.value}
                      onValueChange={(val) => {
                        field.onChange(val)
                        // Reset key-editing flag when switching away from SSH
                        if (val !== 'ssh') setEditingKey(false)
                      }}
                    >
                      <SelectTrigger id="connection_type">
                        <SelectValue placeholder="Select connection type" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="ssh">SSH — direct key-based connection</SelectItem>
                        <SelectItem value="ssm">SSM — AWS Systems Manager Session Manager</SelectItem>
                      </SelectContent>
                    </Select>
                  )}
                />
                {errors.connection_type && (
                  <p className="text-sm text-destructive">{errors.connection_type.message}</p>
                )}
              </div>

              {/* Warning when changing type in edit mode */}
              {typeChanged && (
                <div className="flex items-start gap-2 rounded-md border border-warning/50 bg-warning/10 px-3 py-2">
                  <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-warning" />
                  <p className="text-sm text-warning">
                    Changing connection type from <strong>{originalType.toUpperCase()}</strong> to{' '}
                    <strong>{connectionType.toUpperCase()}</strong>. The previous connection fields
                    will be cleared when you save.
                  </p>
                </div>
              )}

              {/* SSH-specific fields */}
              {connectionType === 'ssh' && (
                <>
                  <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                    <div className="space-y-2">
                      <Label htmlFor="hostname">Hostname *</Label>
                      <Input id="hostname" placeholder="vpn.example.com" {...register('hostname')} />
                      {errors.hostname && (
                        <p className="text-sm text-destructive">{errors.hostname.message}</p>
                      )}
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="ssh_port">SSH Port</Label>
                      <Input
                        id="ssh_port"
                        type="number"
                        min={1}
                        max={65535}
                        placeholder="22"
                        {...register('ssh_port')}
                      />
                      {errors.ssh_port && (
                        <p className="text-sm text-destructive">{errors.ssh_port.message}</p>
                      )}
                    </div>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="ssh_user">SSH User *</Label>
                    <Input id="ssh_user" placeholder="admin" {...register('ssh_user')} />
                    {errors.ssh_user && (
                      <p className="text-sm text-destructive">{errors.ssh_user.message}</p>
                    )}
                  </div>

                  <div className="space-y-2">
                    {isEdit && !editingKey ? (
                      <>
                        <Label>SSH Private Key</Label>
                        <div className="flex items-center gap-3 rounded-md border border-surface-border bg-muted/50 px-3 py-2">
                          <span className="flex-1 text-sm text-muted-foreground">
                            ******* (key stored)
                          </span>
                          <Button
                            type="button"
                            variant="outline"
                            size="sm"
                            onClick={() => setEditingKey(true)}
                          >
                            Change Key
                          </Button>
                        </div>
                      </>
                    ) : (
                      <>
                        <Label htmlFor="ssh_private_key">
                          SSH Private Key {isEdit ? '' : '*'}
                        </Label>
                        <Textarea
                          id="ssh_private_key"
                          placeholder="-----BEGIN OPENSSH PRIVATE KEY-----&#10;...&#10;-----END OPENSSH PRIVATE KEY-----"
                          rows={6}
                          className="font-mono text-xs"
                          {...register('ssh_private_key')}
                        />
                        {isEdit && editingKey && (
                          <Button
                            type="button"
                            variant="ghost"
                            size="sm"
                            onClick={() => setEditingKey(false)}
                          >
                            Cancel key change
                          </Button>
                        )}
                        {errors.ssh_private_key && (
                          <p className="text-sm text-destructive">{errors.ssh_private_key.message}</p>
                        )}
                      </>
                    )}
                  </div>
                </>
              )}

              {/* SSM-specific fields */}
              {connectionType === 'ssm' && (
                <>
                  <div className="space-y-2">
                    <Label htmlFor="ec2_instance_id">EC2 Instance ID *</Label>
                    <Input
                      id="ec2_instance_id"
                      placeholder="i-0e8545d009894bb9d"
                      className="font-mono text-sm"
                      {...register('ec2_instance_id')}
                    />
                    {errors.ec2_instance_id && (
                      <p className="text-sm text-destructive">{errors.ec2_instance_id.message}</p>
                    )}
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="aws_role_arn">
                      IAM Role ARN{' '}
                      <span className="text-muted-foreground font-normal">(optional — empty uses global role)</span>
                    </Label>
                    <Input
                      id="aws_role_arn"
                      placeholder="arn:aws:iam::123456789012:role/MyRole"
                      className="font-mono text-sm"
                      {...register('aws_role_arn')}
                    />
                    {errors.aws_role_arn && (
                      <p className="text-sm text-destructive">{errors.aws_role_arn.message}</p>
                    )}
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="aws_region_override">
                      AWS Region{' '}
                      <span className="text-muted-foreground font-normal">(optional — empty uses global region)</span>
                    </Label>
                    <Input
                      id="aws_region_override"
                      placeholder="us-east-1"
                      {...register('aws_region_override')}
                    />
                    {errors.aws_region_override && (
                      <p className="text-sm text-destructive">{errors.aws_region_override.message}</p>
                    )}
                  </div>
                </>
              )}

              {/* Description — always visible */}
              <div className="space-y-2">
                <Label htmlFor="description">Description</Label>
                <Textarea
                  id="description"
                  placeholder="Optional description..."
                  {...register('description')}
                />
              </div>
            </CardContent>
          </Card>

          <div className="flex items-center justify-between">
            <div>
              {isEdit && (
                <Button
                  type="button"
                  variant="outline"
                  disabled={testingConnection}
                  onClick={handleTestConnection}
                >
                  <Plug className={testingConnection ? 'h-4 w-4 animate-pulse' : 'h-4 w-4'} />
                  {testingConnection ? 'Testing...' : 'Test Connection'}
                </Button>
              )}
            </div>
            <div className="flex items-center gap-3">
              <Button type="button" variant="outline" onClick={() => navigate('/servers')}>
                Cancel
              </Button>
              <Button type="submit" disabled={isSubmitting || mutation.isPending}>
                {mutation.isPending
                  ? isEdit ? 'Saving...' : 'Creating...'
                  : isEdit ? 'Save Changes' : 'Add Server'}
              </Button>
            </div>
          </div>

          {mutation.isError && (
            <div className="rounded-lg border border-destructive/50 bg-destructive/10 p-4">
              <p className="text-sm text-destructive">
                {mutation.error?.response?.data?.detail ?? mutation.error?.message ?? 'An error occurred'}
              </p>
            </div>
          )}
        </form>
      </div>
    </div>
  )
}
