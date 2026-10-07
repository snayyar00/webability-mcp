import { createHash } from 'crypto'
import { createRequire } from 'module'
import type { Server } from '@modelcontextprotocol/sdk/server/index.js'
import type { BeforeSendFn, PostHog as PostHogClient } from '@posthog/mcp'
import type { ServerOptions } from './server.js'

const POSTHOG_HOST = process.env.POSTHOG_HOST || 'https://us.i.posthog.com'
const require = createRequire(import.meta.url)

let posthogMcp: typeof import('@posthog/mcp') | null | undefined
let posthog: PostHogClient | null | undefined
let shutdownRegistered = false
let offNoticeShown = false

function posthogMcpModule(): typeof import('@posthog/mcp') | null {
  const apiKey = process.env.POSTHOG_PROJECT_API_KEY || process.env.POSTHOG_API_KEY || ''
  if (!apiKey || process.env.WEBABILITY_POSTHOG_MCP_ANALYTICS === 'off') {
    if (!apiKey && process.env.WEBABILITY_POSTHOG_MCP_ANALYTICS !== 'off' && !offNoticeShown) {
      offNoticeShown = true
      console.error('[posthog-mcp] analytics off: set POSTHOG_API_KEY to enable MCP usage analytics (details in PRIVACY.md)')
    }
    posthogMcp = null
    return posthogMcp
  }
  if (posthogMcp !== undefined) return posthogMcp

  try {
    posthogMcp = require('@posthog/mcp') as typeof import('@posthog/mcp')
  } catch (err) {
    console.error(`[posthog-mcp] analytics disabled: ${(err as Error).message}`)
    posthogMcp = null
  }
  return posthogMcp
}

function posthogClient(): PostHogClient | null {
  if (posthog !== undefined) return posthog
  const apiKey = process.env.POSTHOG_PROJECT_API_KEY || process.env.POSTHOG_API_KEY || ''
  const mod = posthogMcpModule()
  if (!apiKey || !mod) {
    posthog = null
    return posthog
  }

  posthog = new mod.PostHog(apiKey, {
    host: POSTHOG_HOST,
    flushAt: Number(process.env.POSTHOG_FLUSH_AT || 20),
    flushInterval: Number(process.env.POSTHOG_FLUSH_INTERVAL || 10000),
  })

  if (!shutdownRegistered) {
    shutdownRegistered = true
    const shutdown = () => {
      void posthog?.shutdown()
    }
    process.once('beforeExit', shutdown)
    process.once('SIGINT', () => {
      shutdown()
      process.exit(130)
    })
    process.once('SIGTERM', () => {
      shutdown()
      process.exit(143)
    })
  }

  return posthog
}

const redactSensitiveMcpPayloads: BeforeSendFn = (event) => {
  // WebAbility MCP tool args can include raw HTML snippets, element HTML,
  // screenshots, and full scan results. Keep PostHog MCP's usage metadata
  // (tool name, duration, client, success/failure), but do not ship payloads.
  delete event.properties.$mcp_parameters
  delete event.properties.$mcp_response
  if (isCallerMisuseNoise(event)) return null
  return event
}

// Agent-misuse $exception noise: errors caused by the CALLER (unknown/probe
// tool names, bad or missing arguments, gated features without sign-in),
// not by our code. These flooded error tracking (21 medium issues Oct 3-6)
// with zero product signal. Real backend failures (AI 500s, scan execution
// errors, target-site failures) do not match and still capture.
const MCP_CALLER_MISUSE_PATTERNS: RegExp[] = [
  /Unknown tool: __/, // MCP checkup/verify probe tools
  /__probe/, // probe tool names anywhere in the text
  /unknown argument '/, // invalid argument names
  /\brequired\b/, // missing-argument validation ("X is/are required")
  // Usage-hint validation (no ^ anchor: the text is prefixed with the
  // exception type, e.g. "Error: pass foreground…").
  /pass (foreground|`html`|baselineId)/,
  /must be one of/, // invalid enum values
  /needs a free WebAbility account/, // gated features
  /not signed in/, // same class (visual_audit, start_audit)
  /matches no element/, // bad selector arguments
  /was not actually scanned/, // BLOCKED refusal messages
  /did not reach the real/, // same class
]

function mcpExceptionText(event: { properties?: Record<string, unknown> }): string {
  const props = event.properties ?? {}
  const list = Array.isArray(props.$exception_list) ? props.$exception_list : []
  const parts: string[] = []
  for (const item of list) {
    if (!item || typeof item !== 'object') continue
    const t = (item as Record<string, unknown>).type
    const v = (item as Record<string, unknown>).value
    if (typeof t === 'string' && t) parts.push(t)
    if (typeof v === 'string' && v) parts.push(v)
  }
  return parts.join(': ')
}

export function isCallerMisuseNoise(event: { event?: string; properties?: Record<string, unknown> }): boolean {
  if (event.event !== '$exception') return false
  const text = mcpExceptionText(event)
  return MCP_CALLER_MISUSE_PATTERNS.some((pattern) => pattern.test(text))
}

function hashedAuthToken(token: string): string {
  return createHash('sha256').update(token).digest('hex').slice(0, 32)
}

export function enablePostHogMcpAnalytics(server: Server, opts: ServerOptions): void {
  const mod = posthogMcpModule()
  const client = posthogClient()
  if (!mod || !client) return

  mod.instrument(server, client, {
    beforeSend: redactSensitiveMcpPayloads,
    eventProperties: () => ({
      webability_transport: opts.remote ? 'streamable-http' : 'stdio',
      webability_posthog_payloads_redacted: true,
    }),
    identify: opts.authToken
      ? {
          distinctId: `webability-token:${hashedAuthToken(opts.authToken)}`,
          properties: { auth_source: 'webability_token' },
        }
      : null,
  })
}
