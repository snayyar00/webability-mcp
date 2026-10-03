/**
 * Dogfood 2026-09-27, audit #397: the pipeline's failure reason already ends
 * in a full stop, and get_audit appended another — "…its URL and secret..
 * Steps: …". Drives the real createServer({ remote: true }) with fetch stubbed.
 */
import assert from 'node:assert/strict'
import { afterEach, test } from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import { createServer } from '../src/server.ts'

const realFetch = globalThis.fetch
afterEach(() => {
  globalThis.fetch = realFetch
})

async function getAudit(body: unknown) {
  globalThis.fetch = (async () => new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } })) as typeof fetch
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  const server = createServer({ remote: true, authToken: 'test-token' })
  const client = new Client({ name: 'test', version: '1' }, { capabilities: {} })
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)])
  const res: any = await client.callTool({ name: 'get_audit', arguments: { id: 397, context: 'Checking the failed-audit line.', llm_model: 'test' } })
  return res.content.map((c: any) => c.text).join('\n') as string
}

const steps = [{ step: 'scan', status: 'failed' }, { step: 'viewports', status: 'pending' }]

for (const error of ['page could not be assessed: the tunnel returned HTTP 404: it is closed.', 'scan did not complete: axe-core did not run', 'ends with an ellipsis...']) {
  test(`a failure reason is followed by exactly one full stop: ${JSON.stringify(error)}`, async () => {
    const text = await getAudit({ id: 397, url: 'https://example.com/', status: 'failed', error, steps })
    const line = text.split('\n')[0]
    assert.doesNotMatch(line, /\.\.\s+Steps:/, line)
    assert.match(line, /[^.]\. Steps: scan:failed {2}viewports:pending$/, line)
  })
}

test('a failure with no reason still reads cleanly', async () => {
  const text = await getAudit({ id: 397, url: 'https://example.com/', status: 'failed', steps })
  assert.match(text.split('\n')[0], /— FAILED\. Steps: scan:failed/)
})
