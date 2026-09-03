import { Navigate, Outlet } from 'react-router-dom'
import { Skeleton } from '@/components/ui/skeleton'
import { useAuth } from '@/hooks/useAuth'

/**
 * Route wrapper that enforces authentication.
 *
 * - While auth state is loading, renders a skeleton placeholder.
 * - If not authenticated, renders a <Navigate> to /login.
 *   This avoids the previous useEffect + login() pattern which caused an
 *   infinite retry loop when the OIDC provider was misconfigured.
 * - If authenticated, renders the child Outlet (nested routes).
 *
 * Usage in router:
 *   <Route element={<ProtectedRoute />}>
 *     <Route path="/" element={<DashboardPage />} />
 *   </Route>
 */
export default function ProtectedRoute() {
  const { isAuthenticated, isLoading, profileError } = useAuth()

  if (isLoading) {
    return (
      <div className="p-6 space-y-4">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-4 w-96" />
        <Skeleton className="h-64 w-full" />
      </div>
    )
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />
  }

  if (profileError) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background p-6">
        <div className="w-full max-w-sm rounded-lg border border-border bg-card p-8 text-center">
          <h2 className="mb-2 text-lg font-semibold text-foreground">Authentication error</h2>
          <p className="text-sm text-destructive">
            {profileError?.message ?? 'Unable to load your profile. Please log in again.'}
          </p>
        </div>
      </div>
    )
  }

  return <Outlet />
}
