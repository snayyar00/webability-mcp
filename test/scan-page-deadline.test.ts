/**
 * One time budget per hosted tool call.
 *
 * A slow page used to run the scan to completion (goto alone may take 30s), so
 * the caller cut the request and showed a bare 504. The hosted path stops at
 * one deadline and returns a message that says what to do instead. The deadline
 * sits under the MCP SDK's default request timeout (60 s) and the judge gets
 * all the time the scan has left.
 */
import assert from 'node:assert/strict'
import dnsPromises from 'dns/promises'
import { test } from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import { DEFAULT_REQUEST_TIMEOUT_MSEC } from '@modelcontextprotocol/sdk/shared/protocol.js'

import * as serverModule from '../src/server.ts'
import { judgeWithin } from '../src/deadline.ts'
import { createServer, HOSTED_CALL_DEADLINE_MS } from '../src/server.ts'

const textOf = (res: any) => res.content.map((c: any) => c.text).join('\n')

test('one hosted deadline for every live-scan tool, under the MCP SDK request timeout', () => {
  // 90 days of hosted scan_page (2026-11-26): 3,320 calls, 914 at the old 25 s cap,
  // 0 from Zapier (the client that cap was sized for).
  assert.equal(HOSTED_CALL_DEADLINE_MS, 55_000)
  assert.ok(HOSTED_CALL_DEADLINE_MS < DEFAULT_REQUEST_TIMEOUT_MSEC, 'an SDK client with the default 60 s timeout must get the answer')
  // No per-tool constants left to raise one at a time.
  assert.equal((serverModule as Record<string, unknown>).SCAN_PAGE_HOSTED_DEADLINE_MS, undefined)
  assert.equal((serverModule as Record<string, unknown>).DIFF_SCAN_HOSTED_DEADLINE_MS, undefined)
})

async function slowClient() {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  // 1 ms: the deadline fires while the browser is still launching.
  const server = createServer({ remote: true, authToken: 'test-token', scanPageDeadlineMs: 1 })
  const client = new Client({ name: 'test', version: '1' }, { capabilities: {} })
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)])
  return client
}

test('hosted diff_scan (two live scans) stops at the same deadline', async () => {
  const client = await slowClient()
  const started = Date.now()
  const res: any = await client.callTool({
    name: 'diff_scan',
    arguments: { baselineUrl: 'https://1.1.1.1/', url: 'https://1.0.0.1/', context: 'Checking the hosted diff deadline stops slow scans.' },
  })
  const text = textOf(res)
  assert.equal(res.isError, true)
  assert.match(text, /took longer than 0\.001s to scan/)
  assert.match(text, /start_audit/)
  assert.ok(Date.now() - started < 10_000, 'must return at the deadline, not after both scans')
  await client.close()
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

test('hosted scan_page with a hanging DNS lookup still answers inside the hosted deadline', async () => {
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
  // An operator budget (WEBABILITY_JUDGE_TIMEOUT_MS) still caps it.
  assert.equal({ ...judgeWithin({ timeoutMs: 20_000 }, Date.now() + 60_000)! }.timeoutMs, 20_000)
  // No operator budget: the judge gets all the time the scan has left, not core's 20 s default.
  const open = { ...judgeWithin({ apiUrl: 'https://api.test' }, Date.now() + 40_000)! }.timeoutMs!
  assert.ok(open > 39_000 && open <= 40_000, `judge got ${open}ms with 40s left`)
  // Judge off stays off.
  assert.equal(judgeWithin(undefined, endsAt), undefined)
})

test('hosted diff_scan does not cap the judge: a cut judge on one side would skew the diff', async () => {
  // Both live scans share one deadline. Capping the judge to "time left" gives
  // the baseline its full budget and the current side the remainder, so judge
  // findings would show as fixed / never as new. Better a timeout message than
  // a wrong diff: the judge keeps its own equal budget on both sides.
  const { readFileSync } = await import('node:fs')
  const src = readFileSync(new URL('../src/server.ts', import.meta.url), 'utf8')
  const diff = src.slice(src.indexOf("if (name === 'diff_scan') {"), src.indexOf('const stored = (id: string)'))
  assert.ok(diff.includes('judge: judgeFor(opts)'), 'diff_scan must pass the uncapped judge')
  assert.ok(!diff.includes('judgeWithin('), 'diff_scan must not cap the judge per side')
})
