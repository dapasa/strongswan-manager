import { createContext, useContext, useEffect, useState, useCallback, useMemo } from 'react'
import { useAuth as useOidcAuth } from 'react-oidc-context'
import api, { setTokenGetter } from '@/services/api'

const AuthContext = createContext(null)

const isBypass = import.meta.env.VITE_AUTH_BYPASS === 'true'

/**
 * Bypass provider used when VITE_AUTH_BYPASS=true.
 * Auto-authenticates as admin with no OIDC interaction.
 */
function BypassProvider({ children }) {
  const profile = useMemo(
    () => ({
      id: 0,
      email: 'dev@localhost',
      display_name: 'Dev Bypass',
      role: 'admin',
      is_active: true,
    }),
    [],
  )

  useEffect(() => {
    setTokenGetter(() => 'dev-bypass-token')
  }, [])

  const noop = useCallback(() => {}, [])

  const value = useMemo(
    () => ({
      user: profile,
      role: 'admin',
      isAuthenticated: true,
      isLoading: false,
      profileError: null,
      login: noop,
      logout: noop,
    }),
    [profile, noop],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

/**
 * Real OIDC-backed provider.
 *
 * Wraps react-oidc-context and enriches it with the user profile
 * from our backend (GET /auth/me) which includes the app-specific role.
 */
function OidcProvider({ children }) {
  const oidc = useOidcAuth()
  const [profile, setProfile] = useState(null)
  const [profileLoading, setProfileLoading] = useState(false)
  const [profileError, setProfileError] = useState(null)

  // Wire token getter into Axios so every request gets the Bearer header
  useEffect(() => {
    setTokenGetter(() => oidc.user?.access_token ?? null)
  }, [oidc.user])

  // Listen for auth:expired events dispatched by the Axios 401 interceptor
  useEffect(() => {
    function handleExpired() {
      oidc.signinRedirect()
    }

    window.addEventListener('auth:expired', handleExpired)
    return () => window.removeEventListener('auth:expired', handleExpired)
  }, [oidc])

  // Fetch user profile (including role) from backend after OIDC authentication
  useEffect(() => {
    if (!oidc.isAuthenticated || !oidc.user?.access_token) {
      setProfile(null)
      return
    }

    let cancelled = false
    setProfileLoading(true)
    setProfileError(null)

    api
      .get('/auth/me')
      .then((res) => {
        if (!cancelled) setProfile(res.data)
      })
      .catch((err) => {
        if (!cancelled) setProfileError(err)
      })
      .finally(() => {
        if (!cancelled) setProfileLoading(false)
      })

    return () => {
      cancelled = true
    }
  }, [oidc.isAuthenticated, oidc.user?.access_token])

  const isAuthenticated = oidc.isAuthenticated
  const isLoading = oidc.isLoading || profileLoading

  const login = useCallback(() => {
    oidc.signinRedirect()
  }, [oidc])

  const logout = useCallback(() => {
    oidc.signoutRedirect()
  }, [oidc])

  const value = useMemo(
    () => ({
      /** User profile from GET /auth/me (id, email, display_name, role, is_active) */
      user: profile,
      /** Convenience: user's role string (admin | operator | viewer) */
      role: profile?.role ?? null,
      /** Whether the user is fully authenticated (OIDC + profile loaded) */
      isAuthenticated: isAuthenticated && profile !== null,
      /** True while OIDC or profile request is in-flight */
      isLoading,
      /** Error from profile fetch, if any */
      profileError,
      /** Trigger OIDC login redirect */
      login,
      /** Trigger OIDC logout redirect */
      logout,
    }),
    [profile, isAuthenticated, isLoading, profileError, login, logout],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

/**
 * Main auth context provider — selects bypass or OIDC based on env.
 */
export function AuthContextProvider({ children }) {
  if (isBypass) {
    return <BypassProvider>{children}</BypassProvider>
  }

  return <OidcProvider>{children}</OidcProvider>
}

/**
 * Hook to access auth state from any component.
 *
 * @returns {{ user, role, isAuthenticated, isLoading, profileError, login, logout }}
 */
export function useAuthContext() {
  const ctx = useContext(AuthContext)
  if (ctx === null) {
    throw new Error('useAuthContext must be used within an AuthContextProvider')
  }
  return ctx
}
