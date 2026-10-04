/**
 * P0: the hosted SSRF pre-dispatch guard must cover EVERY URL-carrying arg,
 * including verify_fix aliases (page / pageUrl) and diff_scan baselineUrl.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import { createServer } from '../src/server.ts'
import { HOSTED_URL_ARG_KEYS } from '../src/server.ts'
import { VERIFY_FIX_URL_KEYS } from '../src/verifyFixArgs.ts'

async function call(name: string, args: Record<string, unknown>) {
  const [c, s] = InMemoryTransport.createLinkedPair()
  const server = createServer({ remote: true, authToken: 'test-token' })
  const client = new Client({ name: 'test', version: '1' }, { capabilities: {} })
  await Promise.all([server.connect(s), client.connect(c)])
  const res: any = await client.callTool({ name, arguments: args })
  return res.content.map((x: any) => x.text ?? '').join('\n')
}

test('verify_fix page alias to cloud metadata is blocked', async () => {
  assert.match(await call('verify_fix', { page: 'http://169.254.169.254/', selector: 'a' }), /Blocked URL/)
})
test('verify_fix pageUrl alias to loopback is blocked', async () => {
  assert.match(await call('verify_fix', { pageUrl: 'http://127.0.0.1/', selector: 'a' }), /Blocked URL/)
})
test('diff_scan baselineUrl to private range is blocked', async () => {
  assert.match(await call('diff_scan', { baselineUrl: 'http://10.0.0.1/', url: 'https://example.com' }), /Blocked URL/)
})
test('every verify_fix URL alias key is in the hosted guard list', () => {
  for (const k of VERIFY_FIX_URL_KEYS) assert.ok(HOSTED_URL_ARG_KEYS.includes(k), k)
  assert.ok(HOSTED_URL_ARG_KEYS.includes('baselineUrl'))
})
