import { lazy } from 'react'

const DashboardPage = lazy(() => import('@/pages/DashboardPage'))
const TunnelListPage = lazy(() => import('@/pages/TunnelListPage'))
const TunnelDetailPage = lazy(() => import('@/pages/TunnelDetailPage'))
const TunnelFormPage = lazy(() => import('@/pages/TunnelFormPage'))
const ServerListPage = lazy(() => import('@/pages/ServerListPage'))
const ServerFormPage = lazy(() => import('@/pages/ServerFormPage'))
const AuditLogPage = lazy(() => import('@/pages/AuditLogPage'))
const UserManagementPage = lazy(() => import('@/pages/UserManagementPage'))
const ElevatedAccessPage = lazy(() => import('@/pages/ElevatedAccessPage'))
const CapturesPage = lazy(() => import('@/pages/CapturesPage'))
const NotFoundPage = lazy(() => import('@/pages/NotFoundPage'))
const Login = lazy(() => import('@/pages/Login'))
const Callback = lazy(() => import('@/pages/Callback'))

export const routes = [
  {
    path: '/',
    element: DashboardPage,
  },
  {
    path: '/tunnels',
    element: TunnelListPage,
  },
  {
    path: '/tunnels/new',
    element: TunnelFormPage,
    props: { mode: 'create' },
  },
  {
    path: '/tunnels/:id',
    element: TunnelDetailPage,
  },
  {
    path: '/tunnels/:id/edit',
    element: TunnelFormPage,
    props: { mode: 'edit' },
  },
  {
    path: '/servers',
    element: ServerListPage,
  },
  {
    path: '/servers/new',
    element: ServerFormPage,
    props: { mode: 'create' },
  },
  {
    path: '/servers/:id/edit',
    element: ServerFormPage,
    props: { mode: 'edit' },
  },
  {
    path: '/audit',
    element: AuditLogPage,
  },
  {
    path: '/users',
    element: UserManagementPage,
  },
  {
    path: '/elevated-access',
    element: ElevatedAccessPage,
  },
  {
    path: '/captures',
    element: CapturesPage,
  },
  {
    path: '/login',
    element: Login,
    public: true,
  },
  {
    path: '/auth/callback',
    element: Callback,
    public: true,
  },
  {
    path: '*',
    element: NotFoundPage,
  },
]

export {
  DashboardPage,
  TunnelListPage,
  TunnelDetailPage,
  TunnelFormPage,
  ServerListPage,
  ServerFormPage,
  AuditLogPage,
  UserManagementPage,
  ElevatedAccessPage,
  CapturesPage,
  NotFoundPage,
  Login,
  Callback,
}
