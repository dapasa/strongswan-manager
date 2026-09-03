import { createContext, useContext, useEffect, useState, useCallback, useMemo } from 'react'
import api, { setTokenGetter } from '@/services/api'

const AuthContext = createContext(null)

const TOKEN_KEY = 'vpnmanager_token'

/**
 * Local authentication provider.
 *
 * Stores the JWT in localStorage and validates it on mount by calling
 * GET /auth/me. Provides login(username, password) and logout().
 */
function LocalAuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [isLoading, setIsLoading] = useState(true)
  const [profileError, setProfileError] = useState(null)

  // Wire the stored token into every Axios request
  useEffect(() => {
    setTokenGetter(() => localStorage.getItem(TOKEN_KEY))
  }, [])

  // Listen for 401 events from the Axios interceptor — clear session
  useEffect(() => {
    function handleExpired() {
      localStorage.removeItem(TOKEN_KEY)
      setUser(null)
      setProfileError(new Error('Session expired. Please log in again.'))
    }
    window.addEventListener('auth:expired', handleExpired)
    return () => window.removeEventListener('auth:expired', handleExpired)
  }, [])

  // On mount: validate any stored token by fetching /auth/me
  useEffect(() => {
    const storedToken = localStorage.getItem(TOKEN_KEY)
    if (!storedToken) {
      setIsLoading(false)
      return
    }

    let cancelled = false
    setIsLoading(true)

    api
      .get('/auth/me')
      .then((res) => {
        if (!cancelled) {
          setUser(res.data)
          setProfileError(null)
        }
      })
      .catch(() => {
        if (!cancelled) {
          localStorage.removeItem(TOKEN_KEY)
          setUser(null)
        }
      })
      .finally(() => {
        if (!cancelled) setIsLoading(false)
      })

    return () => {
      cancelled = true
    }
  }, [])

  const login = useCallback(async (username, password) => {
    setProfileError(null)
    const res = await api.post('/auth/token', { username, password })
    const token = res.data.access_token
    localStorage.setItem(TOKEN_KEY, token)
    setTokenGetter(() => localStorage.getItem(TOKEN_KEY))

    // Fetch profile after storing the token
    const profileRes = await api.get('/auth/me')
    setUser(profileRes.data)
  }, [])

  const logout = useCallback(() => {
    localStorage.removeItem(TOKEN_KEY)
    setUser(null)
    setProfileError(null)
  }, [])

  const value = useMemo(
    () => ({
      /** User profile from GET /auth/me */
      user,
      /** Convenience: user's role string (admin | operator | viewer) */
      role: user?.role ?? null,
      /** Whether the user has a validated profile */
      isAuthenticated: user !== null,
      /** True while initial token validation is in-flight */
      isLoading,
      /** Error from last login or profile fetch */
      profileError,
      /** login(username, password) — returns a Promise */
      login,
      /** Clear session */
      logout,
    }),
    [user, isLoading, profileError, login, logout],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

/**
 * Main auth context provider.
 */
export function AuthContextProvider({ children }) {
  return <LocalAuthProvider>{children}</LocalAuthProvider>
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
