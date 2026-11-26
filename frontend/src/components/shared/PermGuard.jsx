import { useAuth } from '@/hooks/useAuth'

/**
 * Renders children only when the current user holds the given Tier 1 or
 * active Tier 2 permission key.
 *
 * - admin:    always rendered (admin bypasses all permission checks)
 * - viewer:   never rendered (falls back)
 * - operator: rendered when permKey is in user.tier1_permissions OR user.active_tier2
 *
 * @param {{ permKey: string, fallback?: React.ReactNode, children: React.ReactNode }} props
 */
export default function PermGuard({ permKey, fallback = null, children }) {
  const { user, role } = useAuth()

  if (role === 'admin') return children
  if (!role || role === 'viewer') return fallback

  const effective = [
    ...(user?.tier1_permissions ?? []),
    ...(user?.active_tier2 ?? []),
  ]
  return effective.includes(permKey) ? children : fallback
}

/**
 * Returns true when the current user holds the given permission key.
 * Convenience hook for conditional logic inside components.
 */
export function useHasPerm(permKey) {
  const { user, role } = useAuth()

  if (role === 'admin') return true
  if (!role || role === 'viewer') return false

  const effective = [
    ...(user?.tier1_permissions ?? []),
    ...(user?.active_tier2 ?? []),
  ]
  return effective.includes(permKey)
}
