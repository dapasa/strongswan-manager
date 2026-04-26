import { NavLink, useLocation } from 'react-router-dom'
import { LayoutDashboard, Network, Server, ScrollText, Users, Shield } from 'lucide-react'
import { cn } from '@/lib/utils'
import RoleGuard from '@/components/shared/RoleGuard'
import { Separator } from '@/components/ui/separator'

const navItems = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/tunnels', label: 'Tunnels', icon: Network },
  { to: '/servers', label: 'Servers', icon: Server },
  { to: '/audit', label: 'Audit Log', icon: ScrollText },
]

const adminItems = [
  { to: '/users', label: 'Users', icon: Users },
]

/**
 * Sidebar navigation component.
 *
 * Renders the app logo, navigation links with icons, and active route
 * highlighting. The Users link is only visible to admin users via RoleGuard.
 *
 * @param {{ className?: string, onNavigate?: () => void }} props
 *   - onNavigate: called after a link is clicked (used to close mobile sidebar)
 */
export default function Sidebar({ className, onNavigate }) {
  return (
    <aside
      className={cn(
        'flex h-full w-64 flex-col bg-sidebar',
        className,
      )}
    >
      {/* Logo / App title */}
      <div className="flex h-14 items-center gap-2 px-4">
        <Shield className="h-6 w-6 text-sidebar-accent" />
        <span className="text-lg font-semibold text-sidebar-foreground">
          VPN Manager
        </span>
      </div>

      <Separator className="bg-sidebar-border" />

      {/* Navigation links */}
      <nav className="flex-1 space-y-1 px-2 py-3">
        {navItems.map((item) => (
          <SidebarLink key={item.to} item={item} onNavigate={onNavigate} />
        ))}

        <RoleGuard requiredRole="admin">
          <Separator className="my-2 bg-sidebar-border" />
          {adminItems.map((item) => (
            <SidebarLink key={item.to} item={item} onNavigate={onNavigate} />
          ))}
        </RoleGuard>
      </nav>
    </aside>
  )
}

function SidebarLink({ item, onNavigate }) {
  const location = useLocation()
  const { to, label, icon: Icon } = item

  // Exact match for "/" but prefix match for other routes
  const isActive =
    to === '/'
      ? location.pathname === '/'
      : location.pathname === to || location.pathname.startsWith(`${to}/`)

  return (
    <NavLink
      to={to}
      onClick={onNavigate}
      className={cn(
        'flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors',
        isActive
          ? 'border-l-2 border-sidebar-accent bg-sidebar-accent/10 text-sidebar-accent-foreground'
          : 'border-l-2 border-transparent text-sidebar-foreground hover:bg-surface-hover hover:text-sidebar-foreground',
      )}
    >
      <Icon className="h-4 w-4 shrink-0" />
      <span>{label}</span>
    </NavLink>
  )
}
