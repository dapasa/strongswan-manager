/**
 * Live iptables command preview.
 * Watches form values and generates the corresponding iptables command string.
 *
 * Can be used in two modes:
 * 1. With `watch` (React Hook Form) — live preview inside forms
 * 2. With `rule` — static preview for existing rules in the list
 */

/**
 * Build an iptables command string from rule fields.
 *
 * @param {{ chain?: string, protocol?: string, source_cidr?: string, dest_cidr?: string, sport?: number, dport?: number, action?: string, state_match?: string[], comment?: string, position?: number }} values
 * @returns {string}
 */
export function buildCommandString(values) {
  if (!values) return ''

  const parts = ['iptables']

  const chain = values.chain
  if (!chain) return ''

  // Use -I with position or -A (append)
  if (values.position != null && values.position >= 0) {
    parts.push(`-I ${chain} ${values.position}`)
  } else {
    parts.push(`-A ${chain}`)
  }

  if (values.protocol && values.protocol !== 'all') {
    parts.push(`-p ${values.protocol}`)
  }

  if (values.source_cidr) {
    parts.push(`-s ${values.source_cidr}`)
  }

  if (values.dest_cidr) {
    parts.push(`-d ${values.dest_cidr}`)
  }

  if (values.sport) {
    parts.push(`--sport ${values.sport}`)
  }

  if (values.dport) {
    parts.push(`--dport ${values.dport}`)
  }

  if (values.state_match?.length > 0) {
    parts.push(`-m state --state ${values.state_match.join(',')}`)
  }

  if (values.comment) {
    parts.push(`-m comment --comment "${values.comment}"`)
  }

  if (values.action) {
    parts.push(`-j ${values.action}`)
  }

  return parts.join(' ')
}

/**
 * Renders the command preview as a monospace code block.
 *
 * @param {{ command?: string, className?: string }} props
 */
export default function CommandPreview({ command, className = '' }) {
  if (!command) {
    return (
      <div className={`rounded-md border border-dashed border-surface-border bg-muted/30 px-3 py-2 ${className}`}>
        <p className="font-mono text-xs text-muted-foreground">
          iptables -A ... (fill in the form to preview)
        </p>
      </div>
    )
  }

  return (
    <div className={`rounded-md border border-surface-border bg-muted/50 px-3 py-2 ${className}`}>
      <code className="font-mono text-xs text-foreground break-all">{command}</code>
    </div>
  )
}
