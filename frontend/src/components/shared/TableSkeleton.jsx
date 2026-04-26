import { Skeleton } from '@/components/ui/skeleton'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'

/**
 * Reusable skeleton loader for tables.
 *
 * @param {{ rows?: number, columns?: number, headers?: string[] }} props
 */
export default function TableSkeleton({ rows = 5, columns = 4, headers }) {
  const colCount = headers?.length ?? columns

  return (
    <div className="rounded-lg border border-surface-border">
      <Table>
        {headers && (
          <TableHeader>
            <TableRow>
              {headers.map((h) => (
                <TableHead key={h}>{h}</TableHead>
              ))}
            </TableRow>
          </TableHeader>
        )}
        <TableBody>
          {Array.from({ length: rows }).map((_, i) => (
            <TableRow key={i}>
              {Array.from({ length: colCount }).map((__, j) => (
                <TableCell key={j}>
                  <Skeleton className="h-4 w-full" />
                </TableCell>
              ))}
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  )
}
