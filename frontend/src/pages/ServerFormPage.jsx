import { useState } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { ArrowLeft, Plug } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Skeleton } from '@/components/ui/skeleton'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { useServer, useCreateServer, useUpdateServer, useTestConnection } from '@/hooks/useServers'

function buildSchema(mode, editingKey) {
  return z.object({
    name: z.string().min(1, 'Name is required').max(255, 'Name must be 255 characters or less'),
    hostname: z.string().min(1, 'Hostname is required').max(255, 'Hostname must be 255 characters or less'),
    ssh_port: z
      .string()
      .transform((v) => (v === '' ? 22 : Number(v)))
      .pipe(z.number().int().min(1, 'Port must be between 1 and 65535').max(65535, 'Port must be between 1 and 65535')),
    ssh_user: z.string().min(1, 'SSH user is required').max(255),
    ssh_private_key: mode === 'create'
      ? z.string().min(1, 'SSH private key is required')
      : editingKey
        ? z.string().min(1, 'SSH private key is required')
        : z.string().optional().default(''),
    description: z.string().optional().default(''),
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

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm({
    resolver: zodResolver(schema),
    defaultValues: {
      name: server.data?.name ?? '',
      hostname: server.data?.hostname ?? '',
      ssh_port: server.data?.ssh_port != null ? String(server.data.ssh_port) : '22',
      ssh_user: server.data?.ssh_user ?? 'admin',
      ssh_private_key: '',
      description: server.data?.description ?? '',
    },
    values: isEdit && server.data ? {
      name: server.data.name ?? '',
      hostname: server.data.hostname ?? '',
      ssh_port: String(server.data.ssh_port ?? 22),
      ssh_user: server.data.ssh_user ?? 'admin',
      ssh_private_key: '',
      description: server.data.description ?? '',
    } : undefined,
  })

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
    const payload = {
      name: values.name,
      hostname: values.hostname,
      ssh_port: values.ssh_port,
      ssh_user: values.ssh_user,
      description: values.description || null,
    }

    // Only include key if provided (required on create, optional on edit)
    if (values.ssh_private_key) {
      payload.ssh_private_key = values.ssh_private_key
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
              : 'Configure a new SSH server connection.'}
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
              <div className="space-y-2">
                <Label htmlFor="name">Name *</Label>
                <Input id="name" placeholder="production-vpn-1" {...register('name')} />
                {errors.name && (
                  <p className="text-sm text-destructive">{errors.name.message}</p>
                )}
              </div>

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
