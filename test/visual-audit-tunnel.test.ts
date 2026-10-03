import assert from 'node:assert/strict'
import { afterEach, test } from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import { createServer } from '../src/server.ts'

const realFetch = globalThis.fetch
afterEach(() => {
  globalThis.fetch = realFetch
})

test('visual_audit refuses a tunnel URL with no secret before opening a browser', async () => {
  let visionCalls = 0
  globalThis.fetch = (async (input: any) => {
    if (String(input).includes('visual-audit')) visionCalls++
    return new Response(null, { status: 204 })
  }) as typeof fetch
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  const server = createServer({ remote: true, authToken: 'test-token' })
  const client = new Client({ name: 'test', version: '1' }, { capabilities: {} })
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)])

  const started = Date.now()
  const res: any = await client.callTool({
    name: 'visual_audit',
    arguments: { url: 'https://tunnel.webability.io/t/29dc0021f320e7f525be802aa18b1b58/', context: 'Verifying a tunnel URL without its secret is refused rather than audited.' },
  })
  const text = res.content.map((c: any) => c.text).join('\n')

  assert.equal(visionCalls, 0)
  assert.match(text, /tunnel_secret/)
  assert.ok(Date.now() - started < 2000, 'refused up front, not after a page load')
})
