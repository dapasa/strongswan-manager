import { Inbox } from 'lucide-react'

/**
 * Reusable empty state placeholder for list views.
 *
 * @param {{
 *   icon?: import('react').ElementType,
 *   title: string,
 *   description?: string,
 *   action?: import('react').ReactNode
 * }} props
 */
export default function EmptyState({
  icon: Icon = Inbox,
  title,
  description,
  action,
}) {
  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-surface-border py-16 px-4">
      <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-muted">
        <Icon className="h-6 w-6 text-muted-foreground" />
      </div>
      <h3 className="mt-4 text-sm font-medium text-foreground">{title}</h3>
      {description && (
        <p className="mt-1 text-sm text-muted-foreground text-center max-w-sm">
          {description}
        </p>
      )}
      {action && <div className="mt-4">{action}</div>}
    </div>
  )
}
