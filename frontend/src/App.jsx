import { Suspense, lazy } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { Skeleton } from '@/components/ui/skeleton'
import ProtectedRoute from '@/components/shared/ProtectedRoute'
import RoleGuard from '@/components/shared/RoleGuard'
import AppLayout from '@/components/layout/AppLayout'

const DashboardPage = lazy(() => import('@/pages/DashboardPage'))
const TunnelListPage = lazy(() => import('@/pages/TunnelListPage'))
const TunnelDetailPage = lazy(() => import('@/pages/TunnelDetailPage'))
const TunnelFormPage = lazy(() => import('@/pages/TunnelFormPage'))
const ServerListPage = lazy(() => import('@/pages/ServerListPage'))
const ServerFormPage = lazy(() => import('@/pages/ServerFormPage'))
const AuditLogPage = lazy(() => import('@/pages/AuditLogPage'))
const UserManagementPage = lazy(() => import('@/pages/UserManagementPage'))
const NotFoundPage = lazy(() => import('@/pages/NotFoundPage'))
const Login = lazy(() => import('@/pages/Login'))
const Callback = lazy(() => import('@/pages/Callback'))

function LoadingFallback() {
  return (
    <div className="p-6 space-y-4">
      <Skeleton className="h-8 w-64" />
      <Skeleton className="h-4 w-96" />
      <Skeleton className="h-64 w-full" />
    </div>
  )
}

export default function App() {
  return (
    <div className="min-h-screen bg-background text-foreground">
      <Suspense fallback={<LoadingFallback />}>
        <Routes>
          {/* Public routes — no auth required */}
          <Route path="/login" element={<Login />} />
          <Route path="/auth/callback" element={<Callback />} />

          {/* Protected routes — require authentication */}
          <Route element={<ProtectedRoute />}>
            <Route element={<AppLayout />}>
              <Route path="/" element={<DashboardPage />} />
              <Route path="/tunnels" element={<TunnelListPage />} />
              <Route path="/tunnels/new" element={
                <RoleGuard requiredRole="operator" fallback={<Navigate to="/tunnels" />}>
                  <TunnelFormPage mode="create" />
                </RoleGuard>
              } />
              <Route path="/tunnels/:id" element={<TunnelDetailPage />} />
              <Route path="/tunnels/:id/edit" element={
                <RoleGuard requiredRole="operator" fallback={<Navigate to="/tunnels" />}>
                  <TunnelFormPage mode="edit" />
                </RoleGuard>
              } />
              <Route path="/servers" element={<ServerListPage />} />
              <Route path="/servers/new" element={
                <RoleGuard requiredRole="admin" fallback={<Navigate to="/servers" />}>
                  <ServerFormPage mode="create" />
                </RoleGuard>
              } />
              <Route path="/servers/:id/edit" element={
                <RoleGuard requiredRole="admin" fallback={<Navigate to="/servers" />}>
                  <ServerFormPage mode="edit" />
                </RoleGuard>
              } />
              <Route path="/audit" element={<AuditLogPage />} />
              <Route path="/users" element={
                <RoleGuard requiredRole="admin" fallback={<Navigate to="/" />}>
                  <UserManagementPage />
                </RoleGuard>
              } />
              <Route path="*" element={<NotFoundPage />} />
            </Route>
          </Route>
        </Routes>
      </Suspense>
    </div>
  )
}
