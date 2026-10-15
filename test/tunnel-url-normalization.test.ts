/**
 * A tunnel URL pasted without its scheme (`tunnel.webability.io/t/<id>/`) must
 * still pair with the secret the caller passed.
 *
 * dispatchTool derived the tunnel target from the RAW args, then normalised the
 * URL args (bare domain -> https://...) afterwards. The raw value failed
 * parseTunnelTarget (no https:), so `tunnel` was null; the normalised value
 * then passed isTunnelUrl, and visual_audit / start_audit answered
 * "this is a webability-tunnel URL but no `tunnel_secret` was passed" to a
 * caller who had passed one (hosted telemetry, 2026-10).
 */
import assert from 'node:assert/strict'
import { afterEach, test } from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import { createServer } from '../src/server.ts'

const BARE = 'tunnel.webability.io/t/29dc0021f320e7f525be802aa18b1b58/digest.html'
const HTTPS = `https://${BARE}`
const SECRET = 'b'.repeat(64)
const CONTEXT = 'Verifying a scheme-less tunnel URL still pairs with its secret.'

const realFetch = globalThis.fetch
afterEach(() => {
  globalThis.fetch = realFetch
})

async function call(name: string, args: Record<string, unknown>) {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  const server = createServer({ remote: true, authToken: 'test-token' })
  const client = new Client({ name: 'test', version: '1' }, { capabilities: {} })
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)])
  const res: any = await client.callTool({ name, arguments: { context: CONTEXT, ...args } })
  return res.content.map((c: any) => c.text).join('\n')
}

test('start_audit: a scheme-less tunnel URL forwards its secret', async () => {
  const bodies: any[] = []
  globalThis.fetch = (async (input: any, init?: any) => {
    if (String(input).includes('/cli/audit') || String(input).includes('/cli/mcp-trial/audit')) {
      bodies.push(JSON.parse(String(init?.body ?? '{}')))
      return new Response(JSON.stringify({ id: 1, status: 'pending' }), { status: 200, headers: { 'Content-Type': 'application/json' } })
    }
    return new Response(null, { status: 204 })
  }) as typeof fetch
  const text = await call('start_audit', { url: BARE, tunnel_secret: SECRET })

  assert.doesNotMatch(text, /no `tunnel_secret` was passed/)
  assert.equal(bodies.length, 1)
  assert.equal(bodies[0].url, HTTPS)
  assert.equal(bodies[0].tunnelSecret, SECRET)
})

test('start_audit: a secret pasted with surrounding whitespace is trimmed', async () => {
  const bodies: any[] = []
  globalThis.fetch = (async (input: any, init?: any) => {
    if (String(input).includes('/cli/audit') || String(input).includes('/cli/mcp-trial/audit')) {
      bodies.push(JSON.parse(String(init?.body ?? '{}')))
      return new Response(JSON.stringify({ id: 1, status: 'pending' }), { status: 200, headers: { 'Content-Type': 'application/json' } })
    }
    return new Response(null, { status: 204 })
  }) as typeof fetch
  await call('start_audit', { url: HTTPS, tunnel_secret: `  ${SECRET}\n` })

  assert.equal(bodies.length, 1)
  assert.equal(bodies[0].tunnelSecret, SECRET)
})

test('visual_audit: a scheme-less tunnel URL is not refused as secret-less', async () => {
  globalThis.fetch = (async () => new Response(null, { status: 204 })) as typeof fetch
  const text = await call('visual_audit', { url: BARE, tunnel_secret: SECRET })

  assert.doesNotMatch(text, /no `tunnel_secret` was passed/)
})

test('every tool that advertises tunnel_secret derives its target from a scheme-less URL', async () => {
  const { tunnelTargetForCall } = await import('../src/server.ts')
  const cases: Array<[string, Record<string, unknown>]> = [
    ['scan_page', { url: BARE }],
    ['flow_scan', { startUrl: BARE }],
    ['verify_fix', { url: BARE }],
    ['verify_fix', { pageUrl: BARE }],
    ['diff_scan', { url: BARE }],
    ['detect_framework', { url: BARE }],
    ['generate_ai_fix', { url: BARE }],
    ['visual_audit', { url: BARE }],
    ['check_color_contrast', { url: BARE }],
    ['check_aria', { url: BARE }],
    ['start_audit', { url: BARE }],
  ]
  for (const [name, args] of cases) {
    const t = tunnelTargetForCall(name, { ...args, tunnel_secret: SECRET })
    assert.ok(t, `${name} dropped the tunnel target for a scheme-less URL`)
    assert.equal(t.secret, SECRET)
    assert.equal(t.id, '29dc0021f320e7f525be802aa18b1b58')
  }
})
