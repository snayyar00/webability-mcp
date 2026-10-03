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

function posthogMcpModule(): typeof import('@posthog/mcp') | null {
  const apiKey = process.env.POSTHOG_PROJECT_API_KEY || process.env.POSTHOG_API_KEY || ''
  if (!apiKey || process.env.WEBABILITY_POSTHOG_MCP_ANALYTICS === 'off') {
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
  // screenshots, and full scan responses. Keep PostHog MCP's usage metadata
  // (tool name, duration, client, success/failure), but do not ship payloads.
  delete event.properties.$mcp_parameters
  delete event.properties.$mcp_response
  return event
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
