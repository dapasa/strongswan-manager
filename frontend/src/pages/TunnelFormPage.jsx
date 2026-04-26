import { useParams, useNavigate, Link } from 'react-router-dom'
import { ArrowLeft } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import TunnelForm from '@/components/tunnels/TunnelForm'
import { useTunnel } from '@/hooks/useTunnels'

/**
 * Page wrapper for tunnel create/edit form.
 *
 * @param {{ mode: 'create' | 'edit' }} props
 */
export default function TunnelFormPage({ mode = 'create' }) {
  const { id } = useParams()
  const navigate = useNavigate()
  const isEdit = mode === 'edit'

  const tunnel = useTunnel(id, { enabled: isEdit })

  if (isEdit && tunnel.isLoading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-4 w-96" />
        <Skeleton className="h-64 w-full" />
      </div>
    )
  }

  if (isEdit && tunnel.isError) {
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

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Button variant="ghost" size="icon" asChild>
          <Link to={isEdit ? `/tunnels/${id}` : '/tunnels'}>
            <ArrowLeft className="h-4 w-4" />
          </Link>
        </Button>
        <div>
          <h1 className="text-2xl font-bold">
            {isEdit ? 'Edit Tunnel' : 'Create Tunnel'}
          </h1>
          <p className="text-sm text-muted-foreground">
            {isEdit
              ? `Editing ${tunnel.data?.name ?? 'tunnel'}`
              : 'Configure a new IPSec VPN tunnel.'}
          </p>
        </div>
      </div>

      <div className="max-w-2xl">
        <TunnelForm
          mode={mode}
          tunnel={isEdit ? tunnel.data : undefined}
        />
      </div>
    </div>
  )
}
