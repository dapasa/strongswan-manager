import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth as useOidcAuth } from 'react-oidc-context'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'

/**
 * OIDC callback page.
 *
 * Handles the authorization code exchange after the identity provider
 * redirects back. Shows a loading state during exchange and redirects
 * to "/" (or a saved return URL) on success.
 */
export default function Callback() {
  const oidc = useOidcAuth()
  const navigate = useNavigate()
  const [error, setError] = useState(null)

  useEffect(() => {
    if (oidc.error) {
      setError(oidc.error.message || 'Authentication failed')
      return
    }

    if (oidc.isAuthenticated) {
      // Redirect to saved return URL or root
      const returnUrl = sessionStorage.getItem('auth_return_url') || '/'
      sessionStorage.removeItem('auth_return_url')
      navigate(returnUrl, { replace: true })
    }
  }, [oidc.isAuthenticated, oidc.error, navigate])

  if (error) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <div className="w-full max-w-sm rounded-lg border border-border bg-surface p-8 text-center">
          <div className="mb-4 text-4xl">!</div>
          <h1 className="mb-2 text-xl font-bold text-foreground">
            Authentication Error
          </h1>
          <p className="mb-6 text-sm text-destructive">{error}</p>
          <Button
            className="w-full"
            onClick={() => {
              setError(null)
              oidc.signinRedirect()
            }}
          >
            Try Again
          </Button>
        </div>
      </div>
    )
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-background">
      <div className="w-full max-w-sm rounded-lg border border-border bg-surface p-8 text-center">
        <div className="mb-4 space-y-2">
          <Skeleton className="mx-auto h-6 w-48" />
          <Skeleton className="mx-auto h-4 w-32" />
        </div>
        <p className="text-sm text-muted-foreground">
          Completing sign-in...
        </p>
      </div>
    </div>
  )
}
