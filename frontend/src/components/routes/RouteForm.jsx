import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { Plus, ChevronDown, ChevronUp } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { useCreateRoute } from '@/hooks/useRoutes'
import { getErrorMessage } from '@/lib/toast'
import AsyncOperationStatus from '@/components/shared/AsyncOperationStatus'

const cidrRegex = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\/(?:3[0-2]|[12]?\d)$/

const routeSchema = z.object({
  cidr: z.string().regex(cidrRegex, 'Must be a valid CIDR (e.g. 10.0.0.0/24)'),
  description: z.string().optional().default(''),
})

/**
 * Inline form for creating a new route within the tunnel detail page.
 * Collapses/expands to save vertical space.
 *
 * @param {{ tunnelId: number|string }} props
 */
export default function RouteForm({ tunnelId }) {
  const [expanded, setExpanded] = useState(false)
  const [operationId, setOperationId] = useState(null)
  const createRoute = useCreateRoute(tunnelId)

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm({
    resolver: zodResolver(routeSchema),
    defaultValues: { cidr: '', description: '' },
  })

  async function onSubmit(values) {
    const payload = {
      cidr: values.cidr,
      description: values.description || null,
    }
    const result = await createRoute.mutateAsync(payload)
    setOperationId(result.operation_id)
    reset()
  }

  function handleOperationCompleted() {
    setOperationId(null)
  }

  if (!expanded) {
    return (
      <Button
        variant="outline"
        size="sm"
        onClick={() => setExpanded(true)}
        className="gap-1.5"
      >
        <Plus className="h-3.5 w-3.5" />
        Add Route
      </Button>
    )
  }

  return (
    <div className="space-y-3 rounded-lg border border-surface-border bg-surface p-4">
      <div className="flex items-center justify-between">
        <h4 className="text-sm font-medium">New Route</h4>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => setExpanded(false)}
        >
          <ChevronUp className="h-4 w-4" />
        </Button>
      </div>

      <form onSubmit={handleSubmit(onSubmit)} className="space-y-3">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div className="space-y-1.5">
            <Label htmlFor="route-cidr">Destination CIDR *</Label>
            <Input
              id="route-cidr"
              placeholder="10.0.0.0/24"
              {...register('cidr')}
            />
            {errors.cidr && (
              <p className="text-xs text-destructive">{errors.cidr.message}</p>
            )}
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="route-description">Description</Label>
            <Input
              id="route-description"
              placeholder="Optional description"
              {...register('description')}
            />
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Button
            type="submit"
            size="sm"
            disabled={createRoute.isPending}
          >
            {createRoute.isPending ? 'Creating...' : 'Create Route'}
          </Button>
          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={() => {
              reset()
              setExpanded(false)
            }}
          >
            Cancel
          </Button>
        </div>

        {createRoute.isError && (
          <p className="text-xs text-destructive">
            {getErrorMessage(createRoute.error)}
          </p>
        )}
      </form>

      {operationId && (
        <AsyncOperationStatus
          operationId={operationId}
          onCompleted={handleOperationCompleted}
        />
      )}
    </div>
  )
}
