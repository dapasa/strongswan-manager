import { useAuth } from '@/hooks/useAuth'
import { hasMinRole } from '@/lib/constants'

/**
 * Conditionally renders children based on the user's role.
 *
 * Uses the role hierarchy: viewer (0) < operator (1) < admin (2).
 * If the user's role is below the required minimum, renders the
 * fallback (defaults to nothing).
 *
 * @param {{ requiredRole: string, fallback?: React.ReactNode, children: React.ReactNode }} props
 *
 * Usage:
 *   <RoleGuard requiredRole="operator">
 *     <Button>Create Tunnel</Button>
 *   </RoleGuard>
 *
 *   <RoleGuard requiredRole="admin" fallback={<Navigate to="/" />}>
 *     <UserManagementPage />
 *   </RoleGuard>
 */
export default function RoleGuard({ requiredRole, fallback = null, children }) {
  const { role } = useAuth()

  if (!role || !hasMinRole(role, requiredRole)) {
    return fallback
  }

  return children
}
