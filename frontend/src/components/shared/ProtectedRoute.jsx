import { useEffect } from 'react'
import { Outlet } from 'react-router-dom'
import { Skeleton } from '@/components/ui/skeleton'
import { useAuth } from '@/hooks/useAuth'

/**
 * Route wrapper that enforces authentication.
 *
 * - While auth state is loading, renders a skeleton placeholder.
 * - If not authenticated, triggers the OIDC login redirect.
 * - If authenticated, renders the child Outlet (nested routes).
 *
 * Usage in router:
 *   <Route element={<ProtectedRoute />}>
 *     <Route path="/" element={<DashboardPage />} />
 *   </Route>
 */
export default function ProtectedRoute() {
  const { isAuthenticated, isLoading, login } = useAuth()

  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      login()
    }
  }, [isLoading, isAuthenticated, login])

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
    // login() was triggered above; render nothing while redirect happens
    return null
  }

  return <Outlet />
}
