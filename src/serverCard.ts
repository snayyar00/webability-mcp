/**
 * Static MCP server card (SEP-1649 / Smithery): GET /.well-known/mcp/server-card.json.
 *
 * Directories such as Smithery read this to show tools, auth and branding
 * without a live MCP handshake. Everything is derived from the running server:
 * the version from version.ts, the tool list from a real in-process tools/list
 * on the hosted server (the same handler the /mcp endpoint answers with).
 * Only the description/icon/homepage are constants; a test pins description to
 * server.json so it cannot drift.
 */
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import { createServer } from './server.js'
import { MCP_VERSION } from './version.js'
import { MCP_PATH, PUBLIC_URL } from './signIn.js'

export const SERVER_CARD_PATH = '/.well-known/mcp/server-card.json'

const DESCRIPTION = 'Free WCAG 2.2/ADA/508 accessibility MCP: scan, AI fixes, verify, vision audit, localhost tunnel'
const HOMEPAGE = 'https://www.webability.io/mcp'
const ICON_URL = 'https://www.webability.io/favicon.ico'

let cached: Promise<Record<string, unknown>> | undefined

async function build(): Promise<Record<string, unknown>> {
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair()
  const server = createServer({ remote: true, anonymous: true })
  const client = new Client({ name: 'server-card', version: MCP_VERSION }, { capabilities: {} })
  try {
    await Promise.all([server.connect(serverSide), client.connect(clientSide)])
    const { tools } = await client.listTools()
    return {
      serverInfo: { name: 'webability', title: 'WebAbility Accessibility', version: MCP_VERSION },
      description: DESCRIPTION,
      homepage: HOMEPAGE,
      iconUrl: ICON_URL,
      icons: [{ src: ICON_URL }],
      transport: { type: 'streamable-http', endpoint: `${PUBLIC_URL}${MCP_PATH}` },
      authentication: {
        required: false,
        schemes: ['oauth2'],
        description:
          'Anonymous works: scan and check tools need no account, under per-IP fair-use limits. ' +
          'OAuth sign-in with a free WebAbility account is optional and unlocks visual_audit, start_audit, get_audit and the site tools.',
      },
      tools,
      resources: [],
      prompts: [],
    }
  } finally {
    await client.close().catch(() => {})
    await server.close().catch(() => {})
  }
}

/** Built once per process (the tool set is static for a given build). */
export function getServerCard(): Promise<Record<string, unknown>> {
  cached ??= build().catch((err) => {
    cached = undefined
    throw err
  })
  return cached
}
