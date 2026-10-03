/**
 * start_audit hands its URL to a server-side pipeline. For a tunnel URL that
 * pipeline must carry the tunnel secret, or the relay answers 401 and the
 * audit reports on the refusal page (audit #394, 2026-09-26).
 *
 * Drives the real createServer({ remote: true }) with fetch stubbed, so this
 * pins what the tool actually sends to the API.
 */
import assert from 'node:assert/strict'
import { afterEach, test } from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import { createServer } from '../src/server.ts'

const TUNNEL_URL = 'https://tunnel.webability.io/t/29dc0021f320e7f525be802aa18b1b58/digest.html'
const SECRET = 'a'.repeat(64)
const CONTEXT = 'Verifying the audit tool forwards a tunnel credential only for tunnel URLs.'

const realFetch = globalThis.fetch
afterEach(() => {
  globalThis.fetch = realFetch
})

function captureFetch() {
  const calls: Array<{ url: string; body: any }> = []
  globalThis.fetch = (async (input: any, init?: any) => {
    const url = String(input)
    if (url.includes('/cli/audit') || url.includes('/cli/mcp-trial/audit')) {
      calls.push({ url, body: JSON.parse(String(init?.body ?? '{}')) })
      return new Response(JSON.stringify({ id: 1, status: 'pending' }), { status: 200, headers: { 'Content-Type': 'application/json' } })
    }
    return new Response(null, { status: 204 })
  }) as typeof fetch
  return calls
}

async function call(args: Record<string, unknown>) {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  const server = createServer({ remote: true, authToken: 'test-token' })
  const client = new Client({ name: 'test', version: '1' }, { capabilities: {} })
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)])
  const res: any = await client.callTool({ name: 'start_audit', arguments: { context: CONTEXT, ...args } })
  return res.content.map((c: any) => c.text).join('\n')
}

test('a tunnel URL with its secret forwards the secret to the audit API', async () => {
  const calls = captureFetch()
  await call({ url: TUNNEL_URL, tunnel_secret: SECRET })

  assert.equal(calls.length, 1)
  assert.equal(calls[0].body.url, TUNNEL_URL)
  assert.equal(calls[0].body.tunnelSecret, SECRET)
})

test('a tunnel URL without a secret is refused before any API call', async () => {
  const calls = captureFetch()
  const text = await call({ url: TUNNEL_URL })

  assert.equal(calls.length, 0, 'the audit must not be queued — it would scan the relay 401 page')
  assert.match(text, /tunnel_secret/)
})

test('an ordinary URL never carries a tunnel secret, even if one is passed', async () => {
  const calls = captureFetch()
  await call({ url: 'https://example.com/', tunnel_secret: SECRET })

  assert.equal(calls.length, 1)
  assert.equal('tunnelSecret' in calls[0].body, false)
})

test('a lookalike host with a tunnel-shaped path is not treated as a tunnel', async () => {
  const calls = captureFetch()
  await call({ url: 'https://example.com/t/29dc0021f320e7f525be802aa18b1b58/', tunnel_secret: SECRET })

  assert.equal(calls.length, 1)
  assert.equal('tunnelSecret' in calls[0].body, false)
})

test('the start_audit schema advertises tunnel_secret', async () => {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  const server = createServer({ remote: true, authToken: 'test-token' })
  const client = new Client({ name: 'test', version: '1' }, { capabilities: {} })
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)])
  const { tools } = await client.listTools()
  const tool = tools.find((t) => t.name === 'start_audit') as any

  assert.ok(tool.inputSchema.properties.tunnel_secret, 'tunnel_secret missing from schema')
  assert.match(tool.description, /keep the tunnel open/i)
})
