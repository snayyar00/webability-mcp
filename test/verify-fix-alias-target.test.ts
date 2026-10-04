/**
 * verify_fix accepts `page` / `pageUrl` for `url`. Everything downstream that
 * reads the target — the tunnel secret pairing, local scan history, hosted
 * telemetry, and the tool's own schema text — must see the same resolved URL.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import { createServer, tunnelTargetForCall } from '../src/server.ts'
import { describeScanTarget } from '../src/scanLog.ts'
import { describeTelemetryTarget } from '../src/telemetry.ts'

const TUNNEL = 'https://tunnel.webability.io/t/29dc0021f320e7f525be802aa18b1b58/'

test('empty or blank url + page/pageUrl alias tunnels the alias target', () => {
  for (const args of [
    { url: '', page: TUNNEL, selector: '#a', tunnel_secret: 's3cret' },
    { url: '   ', pageUrl: TUNNEL, selector: '#a', tunnel_secret: 's3cret' },
    { page: TUNNEL, selector: '#a', tunnel_secret: 's3cret' },
  ]) {
    const t = tunnelTargetForCall('verify_fix', args)
    assert.ok(t, JSON.stringify(args))
    assert.equal(t.id, '29dc0021f320e7f525be802aa18b1b58')
    assert.equal(t.secret, 's3cret')
  }
})

test('a non-empty canonical url wins over the alias for the tunnel target', () => {
  assert.equal(tunnelTargetForCall('verify_fix', { url: 'https://a.test/', page: TUNNEL, tunnel_secret: 's' }), null)
})

test('other tools still tunnel url / startUrl', () => {
  assert.ok(tunnelTargetForCall('scan_page', { url: TUNNEL, tunnel_secret: 's' }))
  assert.ok(tunnelTargetForCall('flow_scan', { startUrl: TUNNEL, tunnel_secret: 's' }))
})

test('scan history and telemetry record the alias URL for verify_fix', () => {
  for (const args of [{ page: 'https://a.test/x', selector: '#a' }, { url: '', pageUrl: 'https://a.test/x', selector: '#a' }]) {
    assert.equal(describeScanTarget('verify_fix', args), 'https://a.test/x', JSON.stringify(args))
    assert.equal(describeTelemetryTarget('verify_fix', args), 'https://a.test/x', JSON.stringify(args))
  }
})

test('verify_fix url description names the page / pageUrl aliases', async () => {
  const [ct, st] = InMemoryTransport.createLinkedPair()
  const server = createServer({})
  const client = new Client({ name: 'test', version: '1' }, { capabilities: {} })
  await Promise.all([server.connect(st), client.connect(ct)])
  const vf = (await client.listTools()).tools.find((t) => t.name === 'verify_fix')!
  const desc = String((vf.inputSchema.properties as any).url.description)
  assert.match(desc, /`page`/)
  assert.match(desc, /`pageUrl`/)
})
