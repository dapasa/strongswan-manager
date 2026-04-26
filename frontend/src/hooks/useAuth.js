/**
 * Re-export the auth context hook for clean imports.
 *
 * Usage:
 *   import { useAuth } from '@/hooks/useAuth'
 *   const { user, role, isAuthenticated, login, logout } = useAuth()
 */
export { useAuthContext as useAuth } from '@/contexts/AuthContext'
