import { LogOut, Menu } from 'lucide-react'
import { useAuth } from '@/hooks/useAuth'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Separator } from '@/components/ui/separator'

const roleBadgeVariant = {
  admin: 'default',
  operator: 'secondary',
  viewer: 'outline',
}

/**
 * Application header bar.
 *
 * Shows a hamburger toggle on mobile, the current user's name/email,
 * their role as a colored badge, and a logout button.
 *
 * @param {{ onToggleSidebar?: () => void }} props
 */
export default function Header({ onToggleSidebar }) {
  const { user, role, logout } = useAuth()

  const displayName = user?.display_name || user?.email || 'User'

  return (
    <header className="flex h-14 items-center gap-4 border-b border-border bg-background px-4">
      {/* Mobile hamburger */}
      <Button
        variant="ghost"
        size="icon"
        className="md:hidden"
        onClick={onToggleSidebar}
        aria-label="Toggle navigation"
      >
        <Menu className="h-5 w-5" />
      </Button>

      {/* Spacer — pushes user info to the right */}
      <div className="flex-1" />

      {/* User info section */}
      <div className="flex items-center gap-3">
        <span className="hidden text-sm text-muted-foreground sm:inline">
          {displayName}
        </span>

        {role && (
          <Badge variant={roleBadgeVariant[role] ?? 'outline'}>
            {role}
          </Badge>
        )}

        <Separator orientation="vertical" className="h-6 bg-border" />

        <Button
          variant="ghost"
          size="sm"
          onClick={logout}
          className="gap-2 text-muted-foreground hover:text-foreground"
        >
          <LogOut className="h-4 w-4" />
          <span className="hidden sm:inline">Logout</span>
        </Button>
      </div>
    </header>
  )
}
