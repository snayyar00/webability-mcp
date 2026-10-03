/**
 * The hosted transport must refuse localhost AND explain the way out.
 *
 * Drives the real createServer({ remote: true }) over an in-memory transport,
 * so this exercises the actual SSRF guard and the actual message — not a mock
 * of either.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import { createServer } from '../src/server.ts'

async function hostedClient() {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  const server = createServer({ remote: true, authToken: 'test-token' })
  const client = new Client({ name: 'test', version: '1' }, { capabilities: {} })
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)])
  return { client, server }
}

test('scan_page against localhost is refused with a way out', async () => {
  const { client } = await hostedClient()
  const res: any = await client.callTool({
    name: 'scan_page',
    arguments: { url: 'http://localhost:3000/dashboard', context: 'Verifying the hosted transport refuses a local dev server with an actionable message.' },
  })
  const text = res.content.map((c: any) => c.text).join('\n')

  assert.match(text, /Blocked URL/, 'still refuses')
  assert.match(text, /npx -y @webability\/mcp/, 'names the server that CAN scan localhost')
  assert.match(text, /runs in our cloud/, 'explains why, so it does not read as a fault')
})

test('flow_scan refuses on a localhost URL anywhere in autoNavigate', async () => {
  const { client } = await hostedClient()
  const res: any = await client.callTool({
    name: 'flow_scan',
    arguments: {
      startUrl: 'https://example.com',
      autoNavigate: ['https://example.com/a', 'http://127.0.0.1:3000/admin'],
      context: 'Verifying a local URL buried in a journey array is still refused by the hosted transport.',
    },
  })
  const text = res.content.map((c: any) => c.text).join('\n')
  assert.match(text, /Blocked URL/)
  assert.match(text, /npx -y @webability\/mcp/)
})

test('the hosted tool list no longer promises localhost', async () => {
  const { client } = await hostedClient()
  const { tools } = await client.listTools()
  const scanPage = tools.find((t: any) => t.name === 'scan_page')!
  assert.match(scanPage.description!, /HOSTED server, localhost and private addresses are refused/)
})

test('cloud metadata is refused WITHOUT the guided message', async () => {
  // Not a dev server — coaching an SSRF probe would be the wrong help.
  const { client } = await hostedClient()
  const res: any = await client.callTool({
    name: 'scan_page',
    arguments: { url: 'http://169.254.169.254/latest/meta-data/', context: 'Verifying the cloud metadata endpoint is refused generically without SSRF guidance.' },
  })
  const text = res.content.map((c: any) => c.text).join('\n')
  assert.match(text, /Blocked URL/)
  assert.doesNotMatch(text, /npx/, 'must not coach a probe')
})
