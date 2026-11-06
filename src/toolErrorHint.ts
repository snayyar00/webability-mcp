/**
 * Machine-readable half of a tool failure: `structuredContent.error`.
 * The prose text block stays as it is for older clients; this adds the three
 * things an agent branches on — a stable `code`, whether a plain retry can
 * work (`retriable`), and the one call to try next (`next`).
 *
 * `code` reuses classifyToolError (telemetry.ts), the same classifier the
 * telemetry events use, so a dashboard code and an agent code never differ.
 */
import { classifyToolError } from './telemetry.js'

export interface ErrorNext {
  tool: string
  args?: Record<string, unknown>
  /** What to do when the next step is not a plain tool call. */
  action?: string
}

export interface ErrorHint {
  code: string
  retriable: boolean
  next: ErrorNext
}

/** Codes where the same call can succeed later without any change. */
const RETRIABLE = new Set(['rate_limited', 'timeout'])
const TRANSIENT_NET = /^(ECONNRESET|ETIMEDOUT|EAI_AGAIN|EHOSTUNREACH)$/

export function errorHint(tool: string, args: Record<string, unknown> | undefined, text: string, override?: Partial<ErrorHint>): ErrorHint {
  const classified = classifyToolError(text)
  const base = classified.split(':')[0]!.trim()
  const detail = classified.slice(base.length + 1).trim()
  // An expired or rejected token is a sign-in problem, not a transient fetch failure.
  const authStatus = base === 'fetch_failed' && /^40[13]$/.test(detail)
  const code = override?.code ?? (authStatus ? 'auth_required' : base)
  const retriable =
    override?.retriable ??
    (RETRIABLE.has(code) || (code === 'fetch_failed' && (/^5\d\d$/.test(detail) || TRANSIENT_NET.test(detail))))
  return { code, retriable, next: override?.next ?? nextFor(code, tool, args) }
}

function nextFor(code: string, tool: string, args: Record<string, unknown> | undefined): ErrorNext {
  switch (code) {
    case 'auth_required':
      return { tool, action: 'sign in to WebAbility (run `webability login`, or connect https://mcp.webability.io/mcp/auth), then repeat this call' }
    case 'rate_limited':
    case 'timeout':
    case 'fetch_failed':
      return { tool, ...(args ? { args } : {}), action: 'wait, then repeat this call' }
    case 'blocked':
    case 'blocked_url':
      return { tool: 'scan_html', action: 'the page cannot be fetched by this server; pass its markup as `html`, or run the local MCP server' }
    case 'unsupported':
      return { tool: 'get_rules', action: 'this tool is not available on this server; see the message for the supported route' }
    case 'invalid_args':
      return { tool, action: 'fix the arguments named in the message, then repeat this call' }
    default:
      return { tool, ...(args ? { args } : {}), action: 'repeat once; if it fails again, report the message' }
  }
}
