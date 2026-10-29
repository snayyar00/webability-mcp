/**
 * Hosted flow_scan is one rate-limited call that launches our browser once
 * per page, so its size is bounded on the hosted server (#201): maxPages is
 * clamped and an oversized autoNavigate list is refused before any DNS
 * lookup or browser work. Local installs scan the caller's own machine and
 * keep whatever they ask for.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import { createServer, flowScanMaxPages, HOSTED_FLOW_MAX_PAGES, HOSTED_FLOW_MAX_URLS } from '../src/server.ts'

async function hostedClient() {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  const server = createServer({ remote: true, authToken: 'test-token' })
  const client = new Client({ name: 'test', version: '1' }, { capabilities: {} })
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)])
  return client
}

const textOf = (res: any) => res.content.map((c: any) => c.text).join('\n')

test('hosted: maxPages is clamped; local keeps the asked value', () => {
  assert.equal(HOSTED_FLOW_MAX_PAGES, 10)
  assert.equal(flowScanMaxPages(undefined, true), 10)
  assert.equal(flowScanMaxPages(5, true), 5)
  assert.equal(flowScanMaxPages(1000, true), HOSTED_FLOW_MAX_PAGES)
  assert.equal(flowScanMaxPages(Infinity, true), HOSTED_FLOW_MAX_PAGES)
  assert.equal(flowScanMaxPages(-3, true), 10)
  assert.equal(flowScanMaxPages('50' as unknown, true), 10)
  // Local: the caller's own machine.
  assert.equal(flowScanMaxPages(undefined, false), 10)
  assert.equal(flowScanMaxPages(1000, false), 1000)
})

test('hosted: an autoNavigate list over the cap is refused before any page work', async () => {
  const client = await hostedClient()
  const autoNavigate = Array.from({ length: HOSTED_FLOW_MAX_URLS }, (_, i) => `https://www.usa.gov/page-${i}`)
  const started = Date.now()
  const res: any = await client.callTool({ name: 'flow_scan', arguments: { startUrl: 'https://www.usa.gov', autoNavigate, context: 'Checking the hosted journey size cap.' } })
  assert.equal(res.isError, true)
  assert.match(textOf(res), new RegExp(`at most ${HOSTED_FLOW_MAX_URLS} URLs`))
  // Refused before the per-URL DNS checks: no network round trips.
  assert.ok(Date.now() - started < 1000, `took ${Date.now() - started} ms`)
})

test('hosted: a list at the cap passes the size check (reaches the address check)', async () => {
  const client = await hostedClient()
  // The last entry is a loopback address, so the call stops at the SSRF
  // check: proof it got past the size check without scanning anything.
  const autoNavigate = [...Array.from({ length: HOSTED_FLOW_MAX_URLS - 2 }, () => '203.0.113.7'), '127.0.0.1:3000/admin']
  const text = textOf(await client.callTool({ name: 'flow_scan', arguments: { startUrl: '203.0.113.7', autoNavigate, context: 'Checking a journey at the cap is accepted.' } }))
  assert.doesNotMatch(text, /at most \d+ URLs/)
  assert.match(text, /Blocked URL/)
})
