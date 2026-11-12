/**
 * ChatGPT (OpenAI Apps SDK) mixed auth on the hosted /mcp/apps path.
 *
 * ChatGPT shows its sign-in UI only when (developers.openai.com/apps-sdk/build/auth):
 * 1. every tool in tools/list declares `securitySchemes` (top level, mirrored
 *    in `_meta` for older clients): `noauth` and/or `oauth2` with scopes, and
 * 2. an unauthenticated call to an account tool returns `isError: true`, a
 *    text `content`, and `_meta["mcp/www_authenticate"]` holding one
 *    WWW-Authenticate challenge with `resource_metadata`, `error` and
 *    `error_description`.
 *
 * Before this path existed the ChatGPT plugin pointed at /mcp, which declares
 * no schemes and answers an anonymous account tool with a plain result (on
 * purpose, see signIn.ts), so OpenAI's review saw "No authentication" and its
 * reviewers never reached the sign-in page. /mcp and /mcp/auth stay unchanged.
 *
 * The SDK Client strips unknown top-level tool keys, so tools/list is read as
 * raw JSON-RPC here.
 */
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

process.env.HOME = mkdtempSync(join(tmpdir(), 'wa-apps-auth-home-'))
delete process.env.WEBABILITY_API_KEY
delete process.env.ABILYO_API_KEY
delete process.env.XDG_CONFIG_HOME
delete process.env.WEBABILITY_SCAN_TELEMETRY
process.env.WEBABILITY_SCAN_LOG = 'off'

import assert from 'node:assert/strict'
import { spawn, type ChildProcess } from 'node:child_process'
import { createServer as createHttp, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { after, afterEach, before, beforeEach, describe, test } from 'node:test'

import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import { createServer } from '../src/server.ts'
import * as signIn from '../src/signIn.ts'

const { ACCOUNT_TOOLS } = signIn
const APPS_PATH = (signIn as any).APPS_MCP_PATH as string
const ARGS = { url: 'https://www.webability.io/', domain: 'webability.io', id: 1 }
const ACCOUNT_SCHEMES = [{ type: 'oauth2', scopes: ['mcp'] }]
const FREE_SCHEMES = [{ type: 'noauth' }, { type: 'oauth2', scopes: ['mcp'] }]

const realFetch = globalThis.fetch
let events: any[] = []

/** A raw JSON-RPC session against an in-memory server: no Client-side schema stripping. */
async function raw(opts: Record<string, unknown>) {
  const [c, s] = InMemoryTransport.createLinkedPair()
  await createServer(opts as any).connect(s)
  const pending = new Map<number, (m: any) => void>()
  c.onmessage = (m: any) => {
    if (m && 'id' in m && pending.has(m.id)) {
      pending.get(m.id)!(m)
      pending.delete(m.id)
    }
  }
  await c.start()
  let id = 0
  const rpc = (method: string, params: unknown = {}) =>
    new Promise<any>((resolve) => {
      const i = ++id
      pending.set(i, resolve)
      void c.send({ jsonrpc: '2.0', id: i, method, params } as any)
    })
  const init = await rpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'apps-test', version: '1' } })
  await c.send({ jsonrpc: '2.0', method: 'notifications/initialized' } as any)
  return { rpc, init, close: () => c.close() }
}

async function listTools(opts: Record<string, unknown>): Promise<any[]> {
  const sess = await raw(opts)
  const r = await sess.rpc('tools/list')
  await sess.close()
  return r.result.tools
}
async function callTool(name: string, args: unknown, opts: Record<string, unknown>) {
  const sess = await raw(opts)
  const r = await sess.rpc('tools/call', { name, arguments: args })
  await sess.close()
  return { result: r.result, text: (r.result?.content ?? []).map((x: any) => x.text).join('\n'), event: events[events.length - 1] }
}

const APPS_ANON = { remote: true, anonymous: true, appsAuth: true }
const MCP_ANON = { remote: true, anonymous: true }

describe('in-memory /mcp/apps server', () => {
  beforeEach(() => {
    events = []
    globalThis.fetch = (async (input: any, init?: any) => {
      const url = String(input)
      if (url.endsWith('/mcp/scan-events')) {
        events.push(JSON.parse(String(init?.body)))
        return new Response(null, { status: 204 })
      }
      return new Response(null, { status: 204 })
    }) as typeof fetch
  })
  afterEach(() => {
    globalThis.fetch = realFetch
  })

  test('APPS_MCP_PATH is /mcp/apps', () => {
    assert.equal(APPS_PATH, '/mcp/apps')
  })

  test('every tool declares securitySchemes, top level and in _meta', async () => {
    const tools = await listTools(APPS_ANON)
    assert.ok(tools.length > 10)
    for (const t of tools) {
      const want = ACCOUNT_TOOLS.has(t.name) ? ACCOUNT_SCHEMES : FREE_SCHEMES
      assert.deepEqual(t.securitySchemes, want, t.name)
      assert.deepEqual(t._meta?.securitySchemes, want, `${t.name} _meta`)
    }
    for (const name of ACCOUNT_TOOLS) assert.ok(tools.some((t) => t.name === name), `${name} listed`)
  })

  test('card tools keep their _meta.ui next to the schemes', async () => {
    const tools = await listTools(APPS_ANON)
    const plain = await listTools(MCP_ANON)
    const cards = plain.filter((t) => t._meta?.ui)
    assert.ok(cards.length > 0, 'some tool has a card')
    for (const card of cards) {
      const t = tools.find((x) => x.name === card.name)
      assert.deepEqual(t._meta.ui, card._meta.ui, card.name)
      assert.ok(t._meta.securitySchemes, card.name)
    }
  })

  test('no tool description or server instructions on /mcp/apps mention AgentID, "free" accounts, or other clients', async () => {
    const tools = await listTools(APPS_ANON)
    for (const t of tools) {
      assert.doesNotMatch(t.description, /AgentID|free WebAbility account|Free with a WebAbility account|\/mcp\/auth|webability login|claude mcp login/i, t.name)
    }
    // OpenAI review: no pricing, subscription offers or promotions outside the
    // one tool whose job is the payment link (create_upgrade_link).
    for (const t of tools.filter((x) => x.name !== 'create_upgrade_link')) {
      assert.doesNotMatch(`${t.title ?? ''} ${t.description}`, /payment|Pro plan|WebAbility Pro|Stripe|30 days|price/i, t.name)
    }
    const sess = await raw(APPS_ANON)
    await sess.close()
    assert.doesNotMatch(sess.init.result.instructions, /AgentID|AgentMail|free WebAbility account|free with account/i)
  })

  for (const tool of ACCOUNT_TOOLS) {
    test(`anonymous ${tool}: isError + one www_authenticate challenge + telemetry auth_required`, async () => {
      const r = await callTool(tool, ARGS, APPS_ANON)
      assert.equal(r.result.isError, true, r.text)
      assert.ok(r.text.length > 0)
      const firstLine = r.text.split('\n')[0]
      assert.match(firstLine, /not signed in/i)
      assert.match(firstLine, /Nothing ran/)
      assert.doesNotMatch(r.text, /claude mcp login|AgentID|\bfree\b/i)
      const err = r.result.structuredContent?.error
      assert.equal(err?.code, 'auth_required', JSON.stringify(r.result.structuredContent))
      assert.equal(err?.next?.tool, tool)
      assert.doesNotMatch(JSON.stringify(r.result.structuredContent), /webability login|\/mcp\/auth|claude mcp login/)
      const ch = r.result._meta?.['mcp/www_authenticate']
      assert.ok(Array.isArray(ch) && ch.length === 1, JSON.stringify(r.result._meta))
      assert.match(ch[0], /^Bearer /)
      assert.ok(ch[0].includes(`resource_metadata="${signIn.resourceMetadataUrl(APPS_PATH)}"`), ch[0])
      assert.match(ch[0], /error="insufficient_scope"/)
      assert.match(ch[0], /error_description="[^"]+"/)
      assert.equal(r.event.tool, tool)
      assert.equal(r.event.ok, false)
      assert.equal(r.event.error, 'auth_required')
    })
  }

  test('a free tool still runs anonymously on /mcp/apps', async () => {
    const r = await callTool('check_color_contrast', { foreground: '#777777', background: '#ffffff' }, APPS_ANON)
    assert.notEqual(r.result.isError, true, r.text)
    assert.equal(r.result._meta?.['mcp/www_authenticate'], undefined)
    assert.match(r.text, /4\.4\d/)
  })

  test('plain /mcp is unchanged: no schemes, no challenge, not isError', async () => {
    const tools = await listTools(MCP_ANON)
    for (const t of tools) {
      assert.equal(t.securitySchemes, undefined, t.name)
      assert.equal(t._meta?.securitySchemes, undefined, t.name)
    }
    assert.match(tools.find((t) => t.name === 'add_site').description, /AgentID/)
    const r = await callTool('start_audit', ARGS, MCP_ANON)
    assert.notEqual(r.result.isError, true)
    assert.equal(r.result._meta?.['mcp/www_authenticate'], undefined)
    assert.match(r.text, /claude mcp login/)
  })
})

// ---------------------------------------------------------------------------
// Real HTTP entry: anonymous /mcp/apps is open (no 401), metadata is served.
// ---------------------------------------------------------------------------
const here = dirname(fileURLToPath(import.meta.url))
const USER_TOKEN = 'wa_live_apps_mixed_auth_token'
let api: Server
let child: ChildProcess
let BASE = ''

describe('HTTP /mcp/apps', () => {
  before(async () => {
    api = createHttp((req, res) => {
      res.setHeader('Content-Type', 'application/json')
      if (req.url === '/cli/whoami') {
        res.statusCode = req.headers.authorization === `Bearer ${USER_TOKEN}` ? 200 : 401
        res.end('{}')
        return
      }
      if (req.url?.startsWith('/cli/audit/')) {
        res.statusCode = req.headers.authorization === `Bearer ${USER_TOKEN}` ? 404 : 401
        res.end('{}')
        return
      }
      res.statusCode = 404
      res.end('{}')
    })
    await new Promise<void>((r) => api.listen(0, '127.0.0.1', r))
    const port = 23000 + Math.floor(Math.random() * 2000)
    BASE = `http://127.0.0.1:${port}`
    child = spawn(join(here, '..', 'node_modules', '.bin', 'tsx'), [join(here, '..', 'src', 'http.ts')], {
      env: {
        ...process.env,
        PORT: String(port),
        WEBABILITY_API_URL: `http://127.0.0.1:${(api.address() as AddressInfo).port}`,
        MCP_PUBLIC_URL: BASE,
        OAUTH_SIGNING_SECRET: 'apps-mixed-auth-secret-0123456789',
        WEBABILITY_API_KEY: 'operator-key-must-never-serve-anon',
        WEBABILITY_SCAN_TELEMETRY: 'off',
        ANON_HEAVY_PER_HOUR: '1',
      },
      stdio: ['ignore', 'ignore', 'inherit'],
    })
    for (let i = 0; i < 100; i++) {
      try {
        if ((await realFetch(`${BASE}/health`)).ok) return
      } catch {}
      await new Promise((r) => setTimeout(r, 200))
    }
    throw new Error('server did not start')
  })
  after(() => {
    child?.kill()
    api?.close()
  })

  let nextId = 1
  async function post(body: unknown, headers: Record<string, string> = {}, path = '/mcp/apps') {
    const res = await realFetch(`${BASE}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...headers },
      body: JSON.stringify(body),
    })
    const text = await res.text()
    let json: any
    try {
      json = JSON.parse(text)
    } catch {}
    return { status: res.status, www: res.headers.get('www-authenticate'), headers: res.headers, json, text }
  }

  test('anonymous initialize on /mcp/apps → 200, no WWW-Authenticate', async () => {
    const r = await post({ jsonrpc: '2.0', id: nextId++, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '0' } } })
    assert.equal(r.status, 200, r.text.slice(0, 300))
    assert.equal(r.www, null)
  })

  test('anonymous tools/list over HTTP carries securitySchemes on the wire', async () => {
    const r = await post({ jsonrpc: '2.0', id: nextId++, method: 'tools/list', params: {} })
    assert.equal(r.status, 200, r.text.slice(0, 300))
    for (const t of r.json.result.tools) {
      assert.ok(Array.isArray(t.securitySchemes) && t.securitySchemes.length > 0, t.name)
      assert.ok(Array.isArray(t._meta?.securitySchemes), t.name)
    }
  })

  test('anonymous start_audit over HTTP → 200 with isError + challenge naming the /mcp/apps metadata', async () => {
    const r = await post({ jsonrpc: '2.0', id: nextId++, method: 'tools/call', params: { name: 'start_audit', arguments: ARGS } })
    assert.equal(r.status, 200, r.text.slice(0, 300))
    assert.equal(r.www, null)
    assert.equal(r.json.result.isError, true)
    const ch = r.json.result._meta['mcp/www_authenticate'][0]
    assert.ok(ch.includes(`resource_metadata="${BASE}/.well-known/oauth-protected-resource/mcp/apps"`), ch)
  })

  test('protected-resource metadata for /mcp/apps → 200, resource names /mcp/apps', async () => {
    const r = await realFetch(`${BASE}/.well-known/oauth-protected-resource/mcp/apps`)
    assert.equal(r.status, 200)
    const j: any = await r.json()
    assert.equal(j.resource, `${BASE}/mcp/apps`)
    assert.deepEqual(j.scopes_supported, ['mcp'])
    assert.deepEqual(j.authorization_servers, [BASE])
  })

  test('authorization-server metadata answers on the /mcp/apps path form too', async () => {
    const r = await realFetch(`${BASE}/.well-known/oauth-authorization-server/mcp/apps`)
    assert.equal(r.status, 200)
    const j: any = await r.json()
    assert.equal(j.issuer, BASE)
  })

  test('signed-in token on /mcp/apps runs the account tool', async () => {
    const r = await post({ jsonrpc: '2.0', id: nextId++, method: 'tools/call', params: { name: 'get_audit', arguments: { id: 1 } } }, { authorization: `Bearer ${USER_TOKEN}` })
    assert.equal(r.status, 200, r.text.slice(0, 300))
    assert.equal(r.json.result._meta?.['mcp/www_authenticate'], undefined)
    assert.match(r.json.result.content.map((c: any) => c.text).join('\n'), /No audit #1 for this account/)
  })

  test('garbage token on /mcp/apps → 401 naming the /mcp/apps metadata', async () => {
    const r = await post({ jsonrpc: '2.0', id: nextId++, method: 'tools/list', params: {} }, { authorization: 'Bearer not-a-real-token' })
    assert.equal(r.status, 401)
    assert.ok(r.www?.includes(`resource_metadata="${BASE}/.well-known/oauth-protected-resource/mcp/apps"`), String(r.www))
  })

  test('garbage token on /mcp/apps: the 401 body names no other client', async () => {
    const r = await post({ jsonrpc: '2.0', id: nextId++, method: 'tools/list', params: {} }, { authorization: 'Bearer not-a-real-token' })
    assert.equal(r.status, 401)
    assert.doesNotMatch(r.text, /webability login|x-webability-token|\/mcp\/auth/)
    assert.match(r.json.error.message, /ChatGPT/)
  })

  test('anonymous limit on /mcp/apps: 200 isError result with the sign-in challenge, not a bare 429', async () => {
    // ANON_HEAVY_PER_HOUR=1: the first page-loading call uses the bucket (a private
    // URL is refused fast, no browser), the second is over the limit.
    const scan = () => ({ jsonrpc: '2.0', id: nextId++, method: 'tools/call', params: { name: 'scan_page', arguments: { url: 'http://10.0.0.5/' } } })
    const first = await post(scan(), { 'x-forwarded-for': '198.51.100.77' })
    assert.equal(first.status, 200, first.text.slice(0, 300))
    const req = scan()
    const r = await post(req, { 'x-forwarded-for': '198.51.100.77' })
    assert.equal(r.status, 200, r.text.slice(0, 300))
    assert.equal(r.www, null)
    assert.ok(r.headers.get('retry-after'), 'Retry-After still set')
    assert.equal(r.json.id, req.id)
    assert.equal(r.json.result.isError, true)
    const text = r.json.result.content.map((c: any) => c.text).join('\n')
    assert.match(text, /per hour/)
    assert.match(text, /resets in \d+ (min|s) \(at \d\d:\d\d UTC\)/)
    assert.match(text, /[Ss]ign in to WebAbility/)
    assert.doesNotMatch(text, /claude mcp login|codex|AgentID|webability login|\/mcp\/auth|\bfree\b/i)
    const ch = r.json.result._meta['mcp/www_authenticate']
    assert.equal(ch.length, 1)
    assert.ok(ch[0].includes(`resource_metadata="${BASE}/.well-known/oauth-protected-resource/mcp/apps"`), ch[0])
    assert.match(ch[0], /error="insufficient_scope"/)
    assert.match(ch[0], /error_description="[^"]+"/)
  })

  test('anonymous limit on plain /mcp is unchanged: 429 JSON-RPC error with the client steps', async () => {
    const r = await post({ jsonrpc: '2.0', id: nextId++, method: 'tools/call', params: { name: 'scan_page', arguments: { url: 'http://10.0.0.5/' } } }, { 'x-forwarded-for': '198.51.100.77' }, '/mcp')
    assert.equal(r.status, 429)
    assert.match(r.json.error.message, /claude mcp login/)
  })

  test('plain /mcp over HTTP still has no schemes', async () => {
    const r = await post({ jsonrpc: '2.0', id: nextId++, method: 'tools/list', params: {} }, {}, '/mcp')
    assert.equal(r.status, 200)
    for (const t of r.json.result.tools) assert.equal(t.securitySchemes, undefined, t.name)
  })
})
