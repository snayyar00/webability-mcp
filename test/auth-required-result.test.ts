/**
 * Sign-in-required is a RESULT, not a tool error. The connector health view
 * counts isError results as request errors ("Degraded, 8.2% request errors"),
 * and an unsigned visual_audit / start_audit call is a normal state, not a
 * server failure. The text still says nothing ran and how to sign in; the
 * telemetry event is ok:false with error "auth_required"; every tool stays in
 * tools/list.
 */
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

process.env.HOME = mkdtempSync(join(tmpdir(), 'wa-auth-home-'))
delete process.env.WEBABILITY_API_KEY
delete process.env.ABILYO_API_KEY
delete process.env.XDG_CONFIG_HOME
delete process.env.WEBABILITY_SCAN_TELEMETRY
process.env.WEBABILITY_SCAN_LOG = 'off'

import assert from 'node:assert/strict'
import { afterEach, beforeEach, test } from 'node:test'

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import { createServer } from '../src/server.ts'
import { ACCOUNT_TOOLS } from '../src/signIn.ts'

const realFetch = globalThis.fetch
let events: any[] = []
beforeEach(() => {
  events = []
  globalThis.fetch = (async (input: any, init?: any) => {
    const url = String(input)
    if (url.endsWith('/mcp/scan-events')) {
      events.push(JSON.parse(String(init?.body)))
      return new Response(null, { status: 204 })
    }
    if (url.includes('/cli/')) return new Response(JSON.stringify({ id: 7, status: 'pending' }), { status: 200, headers: { 'Content-Type': 'application/json' } })
    return new Response(null, { status: 204 })
  }) as typeof fetch
})
afterEach(() => {
  globalThis.fetch = realFetch
})

async function connect(opts: Record<string, unknown>) {
  const [c, s] = InMemoryTransport.createLinkedPair()
  const cl = new Client({ name: 'test', version: '1' }, { capabilities: {} })
  await Promise.all([createServer(opts as any).connect(s), cl.connect(c)])
  return cl
}
async function call(name: string, args: Record<string, unknown>, opts: Record<string, unknown>) {
  const cl = await connect(opts)
  const r: any = await cl.callTool({ name, arguments: args })
  await cl.close()
  return { isError: r.isError === true, text: r.content.map((x: any) => x.text).join('\n'), event: events[events.length - 1] }
}
const ANON = { remote: true, anonymous: true }

test('unsigned visual_audit: isError false, sign-in text, nothing-ran line, telemetry auth_required', async () => {
  const r = await call('visual_audit', { url: 'https://www.webability.io/' }, ANON)
  assert.equal(r.isError, false)
  assert.match(r.text, /visual_audit needs a free WebAbility account/)
  assert.match(r.text, /nothing ran/i)
  assert.match(r.text, /claude mcp login/)
  assert.equal(r.event.tool, 'visual_audit')
  assert.equal(r.event.ok, false)
  assert.equal(r.event.error, 'auth_required')
})

for (const tool of ACCOUNT_TOOLS) {
  test(`unsigned ${tool} (hosted anonymous): not an error, telemetry auth_required`, async () => {
    const r = await call(tool, { url: 'https://www.webability.io/', domain: 'webability.io', id: 1 }, ANON)
    assert.equal(r.isError, false, r.text)
    assert.match(r.text, new RegExp(`${tool} needs a free WebAbility account`))
    assert.equal(r.event.ok, false)
    assert.equal(r.event.error, 'auth_required')
  })
}

test('no token on disk or in env: start_audit / get_audit (hosted, no authToken) and add_site / list_sites (local) are auth results too', async () => {
  const cases = [
    ['start_audit', { url: 'https://www.webability.io/' }, { remote: true }],
    ['get_audit', { id: 1 }, { remote: true }],
    ['add_site', { url: 'https://www.webability.io/' }, {}],
    ['list_sites', {}, {}],
  ] as const
  for (const [tool, args, opts] of cases) {
    const r = await call(tool, args as any, opts)
    assert.equal(r.isError, false, `${tool}: ${r.text}`)
    assert.match(r.text, /free WebAbility account/, tool)
    assert.equal(r.event.ok, false, tool)
    assert.equal(r.event.error, 'auth_required', tool)
  }
})

test('signed-in path is unchanged: start_audit queues and reports ok', async () => {
  const r = await call('start_audit', { url: 'https://www.webability.io/' }, { remote: true, authToken: 'tok' })
  assert.equal(r.isError, false)
  assert.match(r.text, /Audit #7 queued/)
  assert.equal(r.event.ok, true)
  assert.equal('error' in r.event, false)
})

test('signed-in real failures are still tool errors', async () => {
  const r = await call('start_audit', {}, { remote: true, authToken: 'tok' })
  assert.equal(r.isError, true)
  assert.equal(r.event.ok, false)
  assert.match(r.event.error, /^invalid_args/)
})

test('every account tool stays in tools/list for an anonymous connection', async () => {
  const cl = await connect(ANON)
  const names = new Set((await cl.listTools()).tools.map((t) => t.name))
  for (const t of ACCOUNT_TOOLS) assert.ok(names.has(t), t)
})
