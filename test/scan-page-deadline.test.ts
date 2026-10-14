/**
 * Hosted scan_page must answer before Zapier's 30s action limit.
 *
 * A slow page used to run the scan to completion (goto alone may take 30s), so
 * Zapier cut the request and showed the user a bare 504. The hosted path now
 * stops at a deadline and returns a message that says what to do instead.
 */
import assert from 'node:assert/strict'
import dnsPromises from 'dns/promises'
import { test } from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import { createServer, judgeWithin, SCAN_PAGE_HOSTED_DEADLINE_MS } from '../src/server.ts'

const textOf = (res: any) => res.content.map((c: any) => c.text).join('\n')

test('hosted scan_page deadline sits under the 30s Zapier limit', () => {
  assert.ok(SCAN_PAGE_HOSTED_DEADLINE_MS <= 25_000)
})

test('hosted scan_page that runs past its deadline returns a clear error, not a hang', async () => {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  // 1 ms: the deadline fires while the browser is still launching.
  const server = createServer({ remote: true, authToken: 'test-token', scanPageDeadlineMs: 1 })
  const client = new Client({ name: 'test', version: '1' }, { capabilities: {} })
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)])

  const started = Date.now()
  const res: any = await client.callTool({
    name: 'scan_page',
    // A public IP literal: passes the SSRF guard with no DNS lookup.
    arguments: { url: 'https://1.1.1.1/', context: 'Checking the hosted scan deadline stops a slow scan.' },
  })
  const text = textOf(res)
  assert.equal(res.isError, true)
  assert.match(text, /took longer than 0\.001s to scan/)
  assert.match(text, /start_audit/)
  assert.ok(Date.now() - started < 10_000, 'must return at the deadline, not after the full scan')
  await client.close()
})

test('hosted scan_page with a hanging DNS lookup still answers before the 30s limit', async () => {
  const realLookup = dnsPromises.lookup
  ;(dnsPromises as any).lookup = () => new Promise(() => {}) // never resolves
  try {
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
    const server = createServer({ remote: true, authToken: 'test-token' })
    const client = new Client({ name: 'test', version: '1' }, { capabilities: {} })
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)])
    const started = Date.now()
    const res: any = await client.callTool({
      name: 'scan_page',
      arguments: { url: 'https://slow-dns.webability.io/', context: 'Checking a hanging DNS lookup cannot outlast the hosted limit.' },
    })
    assert.equal(res.isError, true)
    assert.ok(Date.now() - started < 10_000, `took ${Date.now() - started}ms`)
    await client.close()
  } finally {
    ;(dnsPromises as any).lookup = realLookup
  }
})

test('hosted judge budget shrinks to the time left, read when the judge starts', async () => {
  const endsAt = Date.now() + 3_000
  const judge = judgeWithin({ apiUrl: 'https://api.test', timeoutMs: 20_000 }, endsAt)!
  // scan() spreads opts.judge when the judge starts (after the engines), so
  // the budget must be live at spread time, not fixed when options are built.
  await new Promise((r) => setTimeout(r, 1_100))
  const atStart = { ...judge }
  assert.ok(atStart.timeoutMs! <= 2_000, `judge got ${atStart.timeoutMs}ms with <2s left`)
  assert.ok(atStart.timeoutMs! >= 1)
  assert.equal(atStart.apiUrl, 'https://api.test')
  // Plenty of time left: the configured budget still caps it.
  assert.equal({ ...judgeWithin({ timeoutMs: 20_000 }, Date.now() + 60_000)! }.timeoutMs, 20_000)
  // Judge off stays off.
  assert.equal(judgeWithin(undefined, endsAt), undefined)
})
