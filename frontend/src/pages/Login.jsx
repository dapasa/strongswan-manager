import { useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '@/hooks/useAuth'
import { Button } from '@/components/ui/button'

/**
 * Login page with an SSO sign-in button.
 *
 * If the user is already authenticated, redirects to /.
 * Otherwise shows a centered card with a "Sign in with SSO" button
 * that triggers the OIDC authorization redirect.
 */
export default function Login() {
  const { isAuthenticated, isLoading, login } = useAuth()
  const navigate = useNavigate()

  useEffect(() => {
    if (!isLoading && isAuthenticated) {
      navigate('/', { replace: true })
    }
  }, [isLoading, isAuthenticated, navigate])

  if (isLoading || isAuthenticated) {
    return null
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-background">
      <div className="w-full max-w-sm rounded-lg border border-border bg-surface p-8 text-center">
        <h1 className="mb-2 text-2xl font-bold text-foreground">
          VPN Manager
        </h1>
        <p className="mb-6 text-sm text-muted-foreground">
          Sign in to manage your StrongSwan VPN infrastructure.
        </p>
        <Button className="w-full" onClick={() => login()}>
          Sign in with SSO
        </Button>
      </div>
    </div>
  )
}
