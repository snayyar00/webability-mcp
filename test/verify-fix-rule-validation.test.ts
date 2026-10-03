/**
 * Persona round 3, P058 F5 — verify_fix must fail closed on unknown rule ids.
 *
 * The old filter (`i.wcag.includes(q) || i.type === q`) matched NOTHING for a
 * rule id from the other namespace ('label' vs the webability 'missing_label'
 * type), so the remaining list came back empty and the tool reported
 * VERIFIED true on an element that still had the violation — including after
 * a real fix was reverted. Unknown ids are now refused BEFORE any scan.
 *
 * In-process server (no browser needed on this path — validation returns first).
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

const { createServer } = await import('../src/server.ts')

async function connect(remote: boolean) {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  const server = createServer(remote ? { remote: true, authToken: 'test-token' } : {})
  const client = new Client({ name: 'test', version: '1' }, { capabilities: {} })
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)])
  return client
}

const call = async (client: InstanceType<typeof Client>, name: string, args: Record<string, unknown>) => {
  const res = await client.callTool({ name, arguments: args })
  return (res as { content: Array<{ type: string; text?: string }> }).content.map((c) => c.text ?? '').join('\n')
}

test('unknown rule id is refused as UNVERIFIED, not silently verified', async () => {
  const client = await connect(false)
  const text = await call(client, 'verify_fix', {
    url: 'https://example.test/',
    selector: 'input#email',
    wcag: 'definitely-not-a-real-rule-xyz',
  })
  assert.match(text, /UNVERIFIED/)
  assert.match(text, /not a known rule id/)
  assert.match(text, /"verified": false/)
  assert.match(text, /"reason": "unknown_rule"/)
})
