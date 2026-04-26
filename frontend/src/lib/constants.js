export const POLL_INTERVAL = 3_000
export const DASHBOARD_REFETCH_INTERVAL = 30_000
export const MAX_POLLS = 100
export const DEFAULT_PAGE_SIZE = 20

export const ROLE_HIERARCHY = {
  viewer: 0,
  operator: 1,
  admin: 2,
}

export function hasMinRole(userRole, requiredRole) {
  return (ROLE_HIERARCHY[userRole] ?? 0) >= (ROLE_HIERARCHY[requiredRole] ?? 0)
}
