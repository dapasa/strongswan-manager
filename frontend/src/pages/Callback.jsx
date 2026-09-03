import { Navigate } from 'react-router-dom'

/**
 * OIDC callback page — kept as a route stub for future OIDC integration.
 *
 * In local auth mode this URL is never reached via a real redirect, but
 * it may be bookmarked or typed. Redirect to /login so the user sees the
 * form rather than an error.
 */
export default function Callback() {
  return <Navigate to="/login" replace />
}
